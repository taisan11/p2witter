use crate::core::{crypto, protocol, rpc};
use crate::config::Config;
use crate::storage::Storage;
use crate::{utils::current_unix_millis};
use std::collections::{HashSet, VecDeque};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{Duration, sleep};

const FULL_RELAY_ATTENUATION: u8 = 6;
const SEEN_MESSAGE_CACHE_CAPACITY: usize = 4096;

/// トランスポート暗号化ユニット（長さ前置き + nonce + 暗号文+タグ）の最大バイト長。
/// プロトコル最大ペイロード(512KiB) + ヘッダ + AEAD オーバーヘッド + 余裕。
const TRANSPORT_MAX_UNIT: usize = 512 * 1024 + 1024;

/// ピアごとのメタ情報。トランスポートセッション鍵 (送信/受信) を保持する。
#[derive(Clone, Debug)]
struct PeerMeta {
    public_key: Vec<u8>,
    x25519_public_key: Option<Vec<u8>>,
    last_valid: bool,
    last_timestamp: u64,
    handle: Option<String>,
    transport_send: Option<[u8; 32]>,
    transport_recv: Option<[u8; 32]>,
    /// この接続が受け入れ侧（incoming）か、自ら接続した（outgoing）か。
    /// 同一ピアへの二重接続を解消するために使う。
    is_incoming: bool,
}

/// プロトコルフレームを送信する。トランスポートセッション鍵が確立されていれば
/// 長さ前置きの ChaCha20-Poly1305 ユニットに暗号化して送る（ホップごと暗号化）。
/// 鍵が未確立（最初の HELLO のみ）の場合は平文のまま送る。
async fn send_frame(
    clients: &mut Vec<TcpStream>,
    peer_meta: &[Option<PeerMeta>],
    idx: usize,
    frame: &[u8],
) -> std::io::Result<()> {
    let unit = match peer_meta.get(idx).and_then(|m| m.as_ref()).and_then(|m| m.transport_send) {
        Some(key) => {
            let sealed = crypto::seal_transport(&key, frame)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "seal failed"))?;
            let mut out = Vec::with_capacity(4 + sealed.len());
            out.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
            out.extend_from_slice(&sealed);
            out
        }
        None => frame.to_vec(),
    };
    clients[idx].write_all(&unit).await
}

fn build_signed_chat(text: &str, pkcs8: &[u8], pubk: &[u8]) -> Option<protocol::Message> {
    let ts = current_unix_millis();
    let mut msg = protocol::Message::chat(text, ts);
    // 署名対象バイトは公開鍵を含むため、署名前に public_key を設定する
    msg.public_key = Some(pubk.to_vec());
    let data = protocol::signing_bytes(&msg);
    let sig = crypto::sign_ed25519(&data, pkcs8).ok()?;
    msg.signature = Some(sig);
    Some(msg)
}

fn build_signed_dm(
    text: &str,
    pkcs8: &[u8],
    pubk: &[u8],
    recipient_x25519_pub: &[u8],
    sender_dm_priv: &[u8],
) -> Option<protocol::Message> {
    let ts = current_unix_millis();
    let encrypted = crypto::encrypt_dm_payload(recipient_x25519_pub, sender_dm_priv, text.as_bytes())
        .ok()?;
    let mut msg = protocol::Message::dm_bytes(encrypted, ts);
    msg.public_key = Some(pubk.to_vec());
    let data = protocol::signing_bytes(&msg);
    let sig = crypto::sign_ed25519(&data, pkcs8).ok()?;
    msg.signature = Some(sig);
    Some(msg)
}

fn verify_signed_message(msg: &protocol::Message, sig: &[u8], pk: &[u8]) -> bool {
    let data = protocol::signing_bytes(msg);
    crypto::verify_ed25519(&data, sig, pk).is_ok()
}

fn build_signed_hello(
    handle: &str,
    pkcs8: &[u8],
    pubk: &[u8],
    x25519_pub: &[u8],
) -> Option<protocol::Message> {
    let ts = current_unix_millis();
    // ペイロード: handle + '\n' + x25519公開鍵(hex) + '\n' + ネットワーク鍵ハッシュ(hex)
    // ネットワーク鍵ハッシュが不一致のピアは同一ネットワークとみなさない。
    let payload = format!(
        "{}\n{}\n{}",
        handle,
        crypto::to_hex(x25519_pub),
        crypto::to_hex(&crypto::network_key_hash())
    );
    let mut msg = protocol::Message::hello(ts, &payload);
    msg.public_key = Some(pubk.to_vec());
    let data = protocol::signing_bytes(&msg);
    let sig = crypto::sign_ed25519(&data, pkcs8).ok()?;
    msg.signature = Some(sig);
    Some(msg)
}

fn relay_probability_percent(attenuation: u8) -> u8 {
    if attenuation <= FULL_RELAY_ATTENUATION {
        return 100;
    }
    if attenuation >= protocol::MAX_ATTENUATION {
        return 0;
    }

    let remaining = (protocol::MAX_ATTENUATION - attenuation) as u16;
    let window = (protocol::MAX_ATTENUATION - FULL_RELAY_ATTENUATION) as u16;
    ((remaining * 100) / window) as u8
}

fn relay_bucket(msg: &protocol::Message, src: usize, dst: usize) -> u8 {
    let mut seed = msg.timestamp
        ^ ((msg.kind as u64) << 56)
        ^ ((msg.attenuation as u64) << 48)
        ^ ((msg.payload.len() as u64) << 16)
        ^ ((src as u64) << 8)
        ^ (dst as u64);
    if let Some(pk) = msg.public_key.as_ref() {
        for (i, b) in pk.iter().take(8).enumerate() {
            seed ^= (*b as u64) << (i * 8);
        }
    }
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    (seed % 100) as u8
}

fn should_relay_to_peer(msg: &protocol::Message, src: usize, dst: usize) -> bool {
    let chance = relay_probability_percent(msg.attenuation);
    chance > 0 && relay_bucket(msg, src, dst) < chance
}

fn message_identity(msg: &protocol::Message) -> [u8; 32] {
    let pk_len = msg.public_key.as_ref().map_or(0, |pk| pk.len());
    let sig_len = msg.signature.as_ref().map_or(0, |sig| sig.len());
    let mut v = Vec::with_capacity(18 + msg.payload.len() + pk_len + sig_len);
    v.push(msg.version);
    v.push(msg.kind);
    v.extend_from_slice(&msg.timestamp.to_be_bytes());
    v.extend_from_slice(&(msg.payload.len() as u32).to_be_bytes());
    v.extend_from_slice(&msg.payload);
    if let Some(pk) = msg.public_key.as_ref() {
        v.extend_from_slice(&(pk.len() as u32).to_be_bytes());
        v.extend_from_slice(pk);
    } else {
        v.extend_from_slice(&0u32.to_be_bytes());
    }
    if let Some(sig) = msg.signature.as_ref() {
        v.extend_from_slice(&(sig.len() as u32).to_be_bytes());
        v.extend_from_slice(sig);
    } else {
        v.extend_from_slice(&0u32.to_be_bytes());
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, &v);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

fn is_duplicate_message(
    msg: &protocol::Message,
    seen_messages: &mut HashSet<[u8; 32]>,
    seen_order: &mut VecDeque<[u8; 32]>,
) -> bool {
    let id = message_identity(msg);
    if seen_messages.contains(&id) {
        return true;
    }
    seen_messages.insert(id);
    seen_order.push_back(id);
    if seen_order.len() > SEEN_MESSAGE_CACHE_CAPACITY {
        if let Some(old) = seen_order.pop_front() {
            seen_messages.remove(&old);
        }
    }
    false
}

/// 待受を開始し、広告トークンを生成して main へ通知する。
/// `advertise` はトークンに載せる外部アドレス（host 部）。
async fn start_listener(
    tx_main: &Sender<rpc::Event>,
    accept_tx: &tokio::sync::mpsc::Sender<(TcpStream, std::net::SocketAddr)>,
    listener_task: &mut Option<tokio::task::JoinHandle<()>>,
    port: &str,
    advertise: &str,
) {
    match TcpListener::bind(format!("0.0.0.0:{}", port)).await {
        Ok(l) => {
            let atx = accept_tx.clone();
            *listener_task = Some(tokio::spawn(async move {
                loop {
                    match l.accept().await {
                        Ok((s, _peer)) => {
                            let _ = atx.send((s, _peer)).await;
                        }
                        Err(_) => break,
                    }
                }
            }));
            let addr = format!("{}:{}", advertise, port);
            let tok = crypto::encrypt_conninfo_to_hex(&addr).unwrap_or_else(|_| "?".into());
            let _ = tx_main
                .send(rpc::Event::Message(format!(
                    "待受開始 (公開アドレス={}, token={})",
                    addr, tok
                )))
                .await;
        }
        Err(e) => {
            let _ = tx_main
                .send(rpc::Event::Message(format!("バインドエラー: {:?}", e)))
                .await;
        }
    }
}

pub async fn network_handler(
    tx_main: Sender<rpc::Event>,
    mut rx_thread: Receiver<rpc::Command>,
    cfg: Config,
    db: Storage,
) {
    tx_main
        .send(rpc::Event::Message("ネットワークスレッド開始".to_string()))
        .await
        .ok();
    // 受け入れ用の専用タスクを立ち上げ、承認済みソケットをこのチャネルへ流す。
    // select! で l.accept() と sleep を競合させると edge-triggered な準備完了が
    // 取りこぼされ接続が永久に受け入れられなくなるため、受け入れは別タスクに分離する。
    let (accept_tx, mut accept_rx) = tokio::sync::mpsc::channel::<(TcpStream, std::net::SocketAddr)>(64);
    let mut listener_task: Option<tokio::task::JoinHandle<()>> = None;
    // トンネルセッション（起動中のみ）。Drop 時に子プロセスが kill される。
    let mut tunnel: Option<crate::core::tunnel::TunnelSession> = None;
    let mut clients: Vec<TcpStream> = Vec::new();
    // 各 client ごとのデコーダ
    let mut decoders: Vec<protocol::Decoder> = Vec::new();
    let mut peer_meta: Vec<Option<PeerMeta>> = Vec::new();
    // 各 client ごとのトランスポート受信生バッファ（長さ前置きユニットを再構成）
    let mut raw_bufs: Vec<Vec<u8>> = Vec::new();
    let mut seen_messages: HashSet<[u8; 32]> = HashSet::new();
    let mut seen_order: VecDeque<[u8; 32]> = VecDeque::new();
    let mut buf = [0u8; 2048];
    // ハンドル（必須）
    let mut handle: String = cfg.get_value("user.handle")
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();

    // 署名用鍵を読む (存在しなければ None)
    let mut pkcs8: Option<Vec<u8>> = None;
    let mut public: Option<Vec<u8>> = None;
    // 起動時に読み込み ( /init 後は再起動で有効 )。将来ホットリロードするなら /reload 等追加。
    if let (Some(pk_hex), Some(pub_hex)) = (
        cfg.get_value("key.pkcs8").and_then(|v| v.as_str().map(|s| s.to_string())),
        cfg.get_value("key.public").and_then(|v| v.as_str().map(|s| s.to_string())),
    ) {
        let pk_bytes = crypto::from_hex(&pk_hex).unwrap_or_default();
        let pub_bytes = crypto::from_hex(&pub_hex).unwrap_or_default();
        if !pk_bytes.is_empty() && !pub_bytes.is_empty() {
            pkcs8 = Some(pk_bytes);
            public = Some(pub_bytes);
        }
    }

    // DM 用 X25519 鍵 (存在しなければ生成して保存)
    let mut x25519_priv: Option<Vec<u8>> = None;
    let mut x25519_pub: Option<Vec<u8>> = None;
    {
        let pk_hex = cfg.get_value("key.x25519").and_then(|v| v.as_str().map(|s| s.to_string()));
        let pub_hex =
            cfg.get_value("key.x25519_pub").and_then(|v| v.as_str().map(|s| s.to_string()));
        match (pk_hex, pub_hex) {
            (Some(pk), Some(pubk)) => {
                let pk_bytes = crypto::from_hex(&pk).unwrap_or_default();
                let pub_bytes = crypto::from_hex(&pubk).unwrap_or_default();
                if pk_bytes.len() == 32 && pub_bytes.len() == 32 {
                    x25519_priv = Some(pk_bytes);
                    x25519_pub = Some(pub_bytes);
                }
            }
            _ => {}
        }
        if x25519_priv.is_none() || x25519_pub.is_none() {
            match crypto::generate_x25519_keypair() {
                Ok((pk, pubk)) => {
                    let _ = cfg.upsert_value_and_save(
                        "key.x25519",
                        toml::Value::String(crypto::to_hex(&pk)),
                    );
                    let _ = cfg.upsert_value_and_save(
                        "key.x25519_pub",
                        toml::Value::String(crypto::to_hex(&pubk)),
                    );
                    x25519_priv = Some(pk);
                    x25519_pub = Some(pubk);
                    let _ = tx_main
                        .send(rpc::Event::Message(
                            "DM用X25519鍵を自動生成しました".to_string(),
                        ))
                        .await;
                }
                Err(_) => {}
            }
        }
    }

    // 宛先ごとの DM 用鍵ペア (Ed25519公開鍵hex -> DM秘密鍵) を読込
    let mut dm_keys: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
    if let Some(tbl) = cfg.get_value("dm_keys").and_then(|v| v.as_table().cloned()) {
        for (k, v) in tbl.iter() {
            if let Some(s) = v.as_str() {
                let bytes = crypto::from_hex(s).unwrap_or_default();
                if bytes.len() == 32 {
                    dm_keys.insert(k.clone(), bytes);
                }
            }
        }
    }
    // 宛先ごとの DM 鍵を取得/生成し、永続化するヘルパ
    fn get_or_create_dm_key(
        cfg: &Config,
        dm_keys: &mut std::collections::HashMap<String, Vec<u8>>,
        recipient_pub_hex: &str,
    ) -> Option<Vec<u8>> {
        if let Some(k) = dm_keys.get(recipient_pub_hex) {
            return Some(k.clone());
        }
        let (pk, _pub) = crypto::generate_x25519_keypair().ok()?;
        let _ = cfg.upsert_value_and_save(
            &format!("dm_keys.{}", recipient_pub_hex),
            toml::Value::String(crypto::to_hex(&pk)),
        );
        dm_keys.insert(recipient_pub_hex.to_string(), pk.clone());
        Some(pk)
    }

    'main_loop: loop {
        // コマンド処理: drain できるだけ読む
        while let Ok(cmd) = rx_thread.try_recv() {
            match cmd {
                rpc::Command::Open { port, public_host } => {
                    if listener_task.is_some() {
                        tx_main
                            .send(rpc::Event::Message(
                                "既に待受中（/open は同時に1つまで）".into(),
                            ))
                            .await
                            .ok();
                    } else {
                        // 広告アドレスを解決: 引数 > config.network.advertise_host > 127.0.0.1
                        let advertise = public_host
                            .filter(|h| !h.trim().is_empty())
                            .or_else(|| {
                                cfg.get_value("network.advertise_host")
                                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                                    .filter(|h| !h.trim().is_empty())
                            })
                            .unwrap_or_else(|| "127.0.0.1".to_string());
                        start_listener(&tx_main, &accept_tx, &mut listener_task, &port, &advertise)
                            .await;
                    }
                }
                rpc::Command::Tunnel { provider, port } => {
                    if listener_task.is_some() {
                        tx_main
                            .send(rpc::Event::Message(
                                "既に待受中（/tunnel の前に /close してください）".into(),
                            ))
                            .await
                            .ok();
                    } else {
                        match port.trim().parse::<u16>() {
                            Ok(p) if (1..=65535).contains(&p) => {
                                match crate::core::tunnel::start(&provider, p).await {
                                Ok(session) => {
                                    let public_addr = session.public_addr().to_string();
                                    tx_main
                                        .send(rpc::Event::Message(format!(
                                            "トンネル確立 ({}): 公開アドレス={}",
                                            provider, public_addr
                                        )))
                                        .await
                                        .ok();
                                    tunnel = Some(session);
                                    // 自動で /open を実行（公開アドレスを広告）
                                    start_listener(
                                        &tx_main,
                                        &accept_tx,
                                        &mut listener_task,
                                        &port,
                                        &public_addr,
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    tx_main
                                        .send(rpc::Event::Message(format!(
                                            "トンネル起動失敗: {}",
                                            e
                                        )))
                                        .await
                                        .ok();
                                }
                            }},
                            Err(e) => {
                                tx_main
                                    .send(rpc::Event::Message(format!(
                                        "ポート番号が不正です: {}",
                                        e
                                    )))
                                    .await
                                    .ok();
                            }
                            Ok(_) => {
                                tx_main
                                    .send(rpc::Event::Message(
                                        "ポート番号は 1〜65535 の範囲で指定してください".into(),
                                    ))
                                    .await
                                    .ok();
                            }
                        }
                    }
                }
                rpc::Command::Connect(token) => {
                    // トークンのみ受け付け。復号失敗ならエラー
                    let target = match crypto::decrypt_conninfo_from_hex(&token) {
                        Ok(s) => s,
                        Err(e) => {
                            tx_main
                                .send(rpc::Event::Message(format!(
                                    "接続トークンの復号エラー: {}",
                                    e
                                )))
                                .await
                                .ok();
                            continue;
                        }
                    };
                    match TcpStream::connect(&target).await {
                        Ok(s) => {
                            clients.push(s);
                            decoders.push(protocol::Decoder::new());
                            // 自ら接続した（outgoing）ので is_incoming=false
                            peer_meta.push(Some(PeerMeta {
                                public_key: Vec::new(),
                                x25519_public_key: None,
                                last_valid: false,
                                last_timestamp: 0,
                                handle: None,
                                transport_send: None,
                                transport_recv: None,
                                is_incoming: false,
                            }));
                            raw_bufs.push(Vec::new());
                            let id = clients.len() - 1;
                            // 接続直後に公開鍵ハンドシェイクを送信
                            if let (Some(pubk), Some(pk), Some(xpub)) =
                                (public.as_ref(), pkcs8.as_ref(), x25519_pub.as_ref())
                            {
                                if let Some(hello) = build_signed_hello(&handle, pk, pubk, xpub) {
                                    let frame = protocol::encode(&hello);
                                    let _ = send_frame(&mut clients, &peer_meta, id, &frame).await;
                                }
                            }
                            tx_main
                                .send(rpc::Event::Message(format!(
                                    "接続完了 (token={}) id={}",
                                    token, id
                                )))
                                .await
                                .ok();
                        }
                        Err(e) => {
                            tx_main
                                .send(rpc::Event::Message(format!(
                                    "接続エラー (token={}): {:?}",
                                    token, e
                                )))
                                .await
                                .ok();
                        }
                    }
                }
                rpc::Command::Close => {
                    if listener_task.is_some() {
                        if let Some(h) = listener_task.take() {
                            h.abort();
                        }
                        // トンネルも一緒に終了（子プロセス kill）
                        tunnel = None;
                        tx_main
                            .send(rpc::Event::Message("待受を終了しました".into()))
                            .await
                            .ok();
                    } else {
                        tx_main
                            .send(rpc::Event::Message("待受は起動していません".into()))
                            .await
                            .ok();
                    }
                }
                rpc::Command::Disconnect(rest) => {
                    if let Ok(id) = rest.trim().parse::<usize>() {
                        if id < clients.len() {
                            clients.remove(id);
                            decoders.remove(id);
                            peer_meta.remove(id);
                            tx_main
                                .send(rpc::Event::Message(format!("切断しました id {}", id)))
                                .await
                                .ok();
                        } else {
                            tx_main
                                .send(rpc::Event::Message(format!("切断: 不正な id {}", id)))
                                .await
                                .ok();
                        }
                    } else {
                        tx_main
                            .send(rpc::Event::Message(format!(
                                "切断: 解析エラー '{}': 数値を指定してください",
                                rest
                            )))
                            .await
                            .ok();
                    }
                }
                rpc::Command::PeerList => {
                    let mut lines = Vec::new();
                    lines.push(format!(
                        "ピア数={} 待受={}",
                        clients.len(),
                        listener_task.is_some()
                    ));
                    for (i, c) in clients.iter().enumerate() {
                        let addr = c
                            .peer_addr()
                            .map(|a| a.to_string())
                            .unwrap_or_else(|_| "?".into());
                        let tok =
                            crypto::encrypt_conninfo_to_hex(&addr).unwrap_or_else(|_| "?".into());
                        let fp = peer_meta
                            .get(i)
                            .and_then(|m| m.as_ref())
                            .map(|m| {
                                let d = ring::digest::digest(&ring::digest::SHA256, &m.public_key);
                                let h = crypto::to_hex(d.as_ref());
                                format!("指紋={}", &h[..16])
                            })
                            .unwrap_or_else(|| "指紋=?".into());
                        lines.push(format!("id={} token={} {}", i, tok, fp));
                    }
                    tx_main
                        .send(rpc::Event::Message(lines.join("\n")))
                        .await
                        .ok();
                }
                rpc::Command::Certs => {
                    let mut lines = vec!["証明書:".to_string()];
                    for (i, meta) in peer_meta.iter().enumerate() {
                        match meta {
                            Some(m) => {
                                let d = ring::digest::digest(&ring::digest::SHA256, &m.public_key);
                                let h = crypto::to_hex(d.as_ref());
                                lines.push(format!(
                                    "id={} 有効={} ts={} 公開鍵長={} 指紋={}",
                                    i,
                                    m.last_valid,
                                    m.last_timestamp,
                                    m.public_key.len(),
                                    &h[..32]
                                ));
                            }
                            None => lines.push(format!("id={} <鍵なし>", i)),
                        }
                    }
                    tx_main
                        .send(rpc::Event::Message(lines.join("\n")))
                        .await
                        .ok();
                }
                rpc::Command::Cert(rest) => {
                    let id = match rest.trim().parse::<usize>() {
                        Ok(id) => id,
                        Err(_) => {
                            tx_main
                                .send(rpc::Event::Message(format!(
                                    "証明書詳細: 解析エラー '{}': 数値を指定してください",
                                    rest
                                )))
                                .await
                                .ok();
                            continue;
                        }
                    };
                    match peer_meta.get(id).and_then(|m| m.as_ref()) {
                        Some(m) => {
                            let d = ring::digest::digest(&ring::digest::SHA256, &m.public_key);
                            let h = crypto::to_hex(d.as_ref());
                            let pk_hex = crypto::to_hex(&m.public_key);
                            let detail = vec![
                                format!("id={}", id),
                                format!("有効={}", m.last_valid),
                                format!("最終タイムスタンプ={}", m.last_timestamp),
                                format!("公開鍵長={}", m.public_key.len()),
                                format!(
                                    "ハンドル={}",
                                    m.handle.as_deref().unwrap_or("<未設定>")
                                ),
                                format!("SHA256指紋={}", h),
                                format!("公開鍵(hex)={}", pk_hex),
                            ];
                            tx_main
                                .send(rpc::Event::Message(detail.join("\n")))
                                .await
                                .ok();
                        }
                        None => {
                            tx_main
                                .send(rpc::Event::Message(format!(
                                    "証明書詳細: id {} は存在しないか鍵がありません",
                                    id
                                )))
                                .await
                                .ok();
                        }
                    }
                }
                rpc::Command::Handle(name) => {
                    if name.starts_with('@') && name.chars().count() < 80 {
                        handle = name.clone();
                        tx_main
                            .send(rpc::Event::Message(format!("ハンドル適用: {}", handle)))
                            .await
                            .ok();
                    } else {
                        tx_main
                            .send(rpc::Event::Message(
                                "/handle は @から始まり80文字未満".into(),
                            ))
                            .await
                            .ok();
                    }
                }
                rpc::Command::Chat(rest) => {
                    // 送信メッセージをプロトコルフレーム化
                    if let (Some(ref pk), Some(ref pubk)) = (pkcs8.as_ref(), public.as_ref()) {
                        // 送信本文にハンドルをプレーンで含める
                        let body = format!("{}: {}", handle, rest);
                        if let Some(m) = build_signed_chat(&body, pk, pubk) {
                            let frame = protocol::encode(&m);
                            let mut remove = Vec::new();
                            for i in 0..clients.len() {
                                if let Err(e) =
                                    send_frame(&mut clients, &peer_meta, i, &frame).await
                                {
                                    tx_main
                                        .send(rpc::Event::Message(format!(
                                            "送信エラー {}: {:?}",
                                            i, e
                                        )))
                                        .await
                                        .ok();
                                    remove.push(i);
                                }
                            }
                            // 保存（送信メタ）
                            let rec = crate::storage::MessageRecord {
                                ts_millis: m.timestamp,
                                recv_ts_millis: current_unix_millis(),
                                kind: crate::storage::MsgKind::Chat,
                                from_peer_id: None,
                                to_peer_id: None,
                                handle: Some(handle.clone()),
                                text: body,
                                signed_ok: Some(true),
                            };
                            let _ = db.store_structured(&rec);
                            for i in remove.into_iter().rev() {
                                clients.remove(i);
                                decoders.remove(i);
                            }
                        } else {
                            tx_main
                                .send(rpc::Event::Message("署名生成失敗".into()))
                                .await
                                .ok();
                        }
                    } else {
                        tx_main
                            .send(rpc::Event::Message("鍵未生成 (/init を先に実行)".into()))
                            .await
                            .ok();
                    }
                }
                rpc::Command::DM(to_str, msg_body) => {
                    // /dm <to_id> <message>
                    if let Ok(target) = to_str.parse::<usize>() {
                        if target < clients.len() {
                            if let (Some(ref pk), Some(ref pubk)) =
                                (pkcs8.as_ref(), public.as_ref())
                            {
                                // 宛先の X25519 公開鍵と Ed25519 公開鍵(識別用) を取得
                                let meta = peer_meta
                                    .get(target)
                                    .and_then(|m| m.as_ref())
                                    .cloned();
                                let recipient_x25519 = meta
                                    .as_ref()
                                    .and_then(|m| m.x25519_public_key.clone());
                                let recipient_pub_bytes = meta
                                    .as_ref()
                                    .map(|m| m.public_key.clone())
                                    .unwrap_or_default();
                                let recipient_x25519 = match recipient_x25519 {
                                    Some(k) if k.len() == 32 => k,
                                    _ => {
                                        tx_main
                                            .send(rpc::Event::Message(
                                                "相手のDM公開鍵がありません(HELLO未完了?)".into(),
                                            ))
                                            .await
                                            .ok();
                                        continue;
                                    }
                                };
                                let recipient_pub_hex = match recipient_pub_bytes.len() {
                                    32 => crypto::to_hex(&recipient_pub_bytes),
                                    _ => {
                                        tx_main
                                            .send(rpc::Event::Message(
                                                "相手の公開鍵がありません".into(),
                                            ))
                                            .await
                                            .ok();
                                        continue;
                                    }
                                };
                                // 宛先ごとの DM 鍵を取得/生成 (既知なら再利用)
                                let sender_dm_priv =
                                    match get_or_create_dm_key(&cfg, &mut dm_keys, &recipient_pub_hex) {
                                        Some(k) => k,
                                        None => {
                                            tx_main
                                                .send(rpc::Event::Message(
                                                    "DM鍵生成に失敗".into(),
                                                ))
                                                .await
                                                .ok();
                                            continue;
                                        }
                                    };
                                let body = format!("{}: {}", handle, msg_body);
                                if let Some(m) = build_signed_dm(
                                    &body,
                                    pk,
                                    pubk,
                                    &recipient_x25519,
                                    &sender_dm_priv,
                                ) {
                                    let frame = protocol::encode(&m);
                                    if let Err(e) =
                                        send_frame(&mut clients, &peer_meta, target, &frame).await
                                    {
                                        tx_main
                                            .send(rpc::Event::Message(format!(
                                                "DM送信エラー {}: {:?}",
                                                target, e
                                            )))
                                            .await
                                            .ok();
                                    }
                                    // 保存（送信メタ）
                                    let rec = crate::storage::MessageRecord {
                                        ts_millis: m.timestamp,
                                        recv_ts_millis: current_unix_millis(),
                                        kind: crate::storage::MsgKind::Dm,
                                        from_peer_id: None,
                                        to_peer_id: Some(target),
                                        handle: Some(handle.clone()),
                                        text: body,
                                        signed_ok: Some(true),
                                    };
                                    let _ = db.store_structured(&rec);
                                } else {
                                    tx_main
                                        .send(rpc::Event::Message("DM署名生成失敗".into()))
                                        .await
                                        .ok();
                                }
                            } else {
                                tx_main
                                    .send(rpc::Event::Message("鍵未生成 (/init を先に実行)".into()))
                                    .await
                                    .ok();
                            }
                        } else {
                            tx_main
                                .send(rpc::Event::Message(format!(
                                    "DM 宛先 id {} が範囲外です",
                                    target
                                )))
                                .await
                                .ok();
                        }
                    } else {
                        tx_main
                            .send(rpc::Event::Message(format!("不正な DM 宛先: {}", to_str)))
                            .await
                            .ok();
                    }
                }
                rpc::Command::Shutdown => {
                    // トンネル子プロセスを終了
                    tunnel = None;
                    tx_main
                        .send(rpc::Event::Message("ネットワークスレッド終了".into()))
                        .await
                        .ok();
                    break 'main_loop;
                }
            }
        }

        // 受け入れ専用タスクからソケットを受け取る（edge-triggered を取りこぼさない）
        let mut accepted: Option<(TcpStream, std::net::SocketAddr)> = None;
        if let Ok((s, peer)) = accept_rx.try_recv() {
            accepted = Some((s, peer));
        }
        if let Some((s, peer)) = accepted {
            clients.push(s);
            decoders.push(protocol::Decoder::new());
            // 受け入れ側（incoming）なので is_incoming=true
            peer_meta.push(Some(PeerMeta {
                public_key: Vec::new(),
                x25519_public_key: None,
                last_valid: false,
                last_timestamp: 0,
                handle: None,
                transport_send: None,
                transport_recv: None,
                is_incoming: true,
            }));
            raw_bufs.push(Vec::new());
            // 受け入れ側も公開鍵を送信
            let id = clients.len() - 1;
            if let (Some(pubk), Some(pk), Some(xpub)) =
                (public.as_ref(), pkcs8.as_ref(), x25519_pub.as_ref())
            {
                if let Some(hello) = build_signed_hello(&handle, pk, pubk, xpub) {
                    let frame = protocol::encode(&hello);
                    let _ = send_frame(&mut clients, &peer_meta, id, &frame).await;
                }
            }
            let token = crypto::encrypt_conninfo_to_hex(&peer.to_string())
                .unwrap_or_else(|_| "?".to_string());
            tx_main
                .send(rpc::Event::Message(format!(
                    "接続受入 (token={}) id={}",
                    token, id
                )))
                .await
                .ok();
        }

        // 読み取り (バイナリプロトコル優先)
        let mut received_frames: Vec<(usize, protocol::Message)> = Vec::new();
        let mut remove_indices: Vec<usize> = Vec::new();
        for (idx, c) in clients.iter_mut().enumerate() {
            match c.try_read(&mut buf) {
                Ok(0) => {
                    tx_main
                        .send(rpc::Event::Message(format!(
                            "クライアント {} が切断しました",
                            idx
                        )))
                        .await
                        .ok();
                    remove_indices.push(idx);
                }
                Ok(n) => {
                    if n > 0 {
                        let data = &buf[..n];
                        // トランスポートセッション鍵（受信）が確立されていれば
                        // 長さ前置き暗号化ユニットを復号してからプロトコルデコーダへ流す。
                        // 鍵未確立（最初の HELLO のみ）は平文のまま渡す。
                        let transport_key =
                            peer_meta.get(idx).and_then(|m| m.as_ref()).and_then(|m| m.transport_recv);
                        if let Some(key) = transport_key {
                            raw_bufs[idx].extend_from_slice(data);
                            let mut drop_peer = false;
                            loop {
                                if raw_bufs[idx].len() < 4 {
                                    break;
                                }
                                let len = u32::from_be_bytes([
                                    raw_bufs[idx][0],
                                    raw_bufs[idx][1],
                                    raw_bufs[idx][2],
                                    raw_bufs[idx][3],
                                ]) as usize;
                                if len == 0 || len > TRANSPORT_MAX_UNIT {
                                    drop_peer = true;
                                    break;
                                }
                                if raw_bufs[idx].len() < 4 + len {
                                    break;
                                }
                                let unit: Vec<u8> = raw_bufs[idx][4..4 + len].to_vec();
                                raw_bufs[idx].drain(..4 + len);
                                match crypto::open_transport(&key, &unit) {
                                    Ok(plain) => decoders[idx].feed(&plain),
                                    Err(_) => {
                                        drop_peer = true;
                                        break;
                                    }
                                }
                            }
                            if drop_peer {
                                tx_main
                                    .send(rpc::Event::Message(format!(
                                        "トランスポートエラー {}: 切断",
                                        idx
                                    )))
                                    .await
                                    .ok();
                                remove_indices.push(idx);
                            } else {
                                match decoders[idx].drain() {
                                    Ok(mut msgs) => {
                                        for m in msgs.drain(..) {
                                            received_frames.push((idx, m));
                                        }
                                    }
                                    Err(e) => {
                                        tx_main
                                            .send(rpc::Event::Message(format!(
                                                "プロトコルエラー {}: {}",
                                                idx, e
                                            )))
                                            .await
                                            .ok();
                                        remove_indices.push(idx);
                                    }
                                }
                            }
                        } else {
                            decoders[idx].feed(data);
                            match decoders[idx].drain() {
                                Ok(mut msgs) => {
                                    for m in msgs.drain(..) {
                                        received_frames.push((idx, m));
                                    }
                                }
                                Err(e) => {
                                    tx_main
                                        .send(rpc::Event::Message(format!(
                                            "プロトコルエラー {}: {}",
                                            idx, e
                                        )))
                                        .await
                                        .ok();
                                    remove_indices.push(idx);
                                }
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    tx_main
                        .send(rpc::Event::Message(format!("受信エラー {}: {:?}", idx, e)))
                        .await
                        .ok();
                    remove_indices.push(idx);
                }
            }
        }

        // 中継と表示 + 署名検証
        // dropped: この処理ループ内で既に切断予定となった src を記録し、
        // 同一 src の後続フレームをスキップしてインデックスずれを防ぐ。
        let mut dropped: HashSet<usize> = HashSet::new();
        for (src, msg) in received_frames.iter() {
            if dropped.contains(src) {
                continue;
            }
            // タイムスタンプ検証: 未来すぎる/過去すぎるメッセージは不正(リプレイ等)として破棄
            const TS_FUTURE_SKEW: u64 = 5 * 60 * 1000; // 5分
            const TS_MIN: u64 = 1_700_000_000_000; // 2023-11 頃以降のみ許可
            let now = current_unix_millis();
            if msg.timestamp > now.saturating_add(TS_FUTURE_SKEW) || msg.timestamp < TS_MIN {
                tx_main
                    .send(rpc::Event::Message(format!(
                        "不正なタイムスタンプを破棄 id={} ts={}",
                        src, msg.timestamp
                    )))
                    .await
                    .ok();
                continue;
            }
            if (msg.kind == protocol::MsgKind::CHAT || msg.kind == protocol::MsgKind::DM)
                && is_duplicate_message(msg, &mut seen_messages, &mut seen_order)
            {
                continue;
            }
            // テキスト復号/デコード
            let txt = if msg.kind == protocol::MsgKind::DM {
                match x25519_priv.as_ref() {
                    Some(priv_key) => {
                        match crypto::decrypt_dm_payload(priv_key, &msg.payload) {
                            Ok(p) => String::from_utf8_lossy(&p).to_string(),
                            Err(_) => "<DM復号エラー>".to_string(),
                        }
                    }
                    None => "<DM鍵未設定>".to_string(),
                }
            } else {
                String::from_utf8_lossy(&msg.payload).to_string()
            };
            let mut signed_state = if msg.signature.is_some() {
                "○"
            } else {
                "・"
            };
            let mut good = true;
            if let (Some(sig), Some(pk)) = (msg.signature.as_ref(), msg.public_key.as_ref()) {
                if !verify_signed_message(msg, sig, pk) {
                    signed_state = "×";
                    good = false;
                }
                // メタ更新（既存のハンドル情報は維持）
                if *src < peer_meta.len() {
                    let existing_handle = peer_meta[*src].as_ref().and_then(|m| m.handle.clone());
                    let existing_x25519 = peer_meta[*src]
                        .as_ref()
                        .and_then(|m| m.x25519_public_key.clone());
                    let (transport_send, transport_recv, is_incoming) = peer_meta[*src]
                        .as_ref()
                        .map(|m| (m.transport_send, m.transport_recv, m.is_incoming))
                        .unwrap_or((None, None, false));
                    peer_meta[*src] = Some(PeerMeta {
                        public_key: pk.clone(),
                        x25519_public_key: existing_x25519,
                        last_valid: good,
                        last_timestamp: msg.timestamp,
                        handle: existing_handle,
                        transport_send,
                        transport_recv,
                        is_incoming,
                    });
                }
            }
            if msg.kind == protocol::MsgKind::DISCONNECT {
                let reason = protocol::disconnect_reason_id(msg).unwrap_or(0);
                tx_main
                    .send(rpc::Event::Message(format!(
                        "相手から切断通知 id={} reason={}",
                        src, reason
                    )))
                    .await
                    .ok();
                dropped.insert(*src);
                        remove_indices.push(*src);
            } else if msg.kind == protocol::MsgKind::HELLO {
                // 相手の公開鍵が含まれていれば保存
                if let Some(pk) = msg.public_key.as_ref() {
                    // HELLO 自体の署名検証
                    if let Some(sig) = msg.signature.as_ref() {
                        if !verify_signed_message(msg, sig, pk) {
                            // 理由ID=3: HELLO署名不正
                            let disc = protocol::Message::disconnect(current_unix_millis(), 3);
                            let frame = protocol::encode(&disc);
                            let _ = send_frame(&mut clients, &peer_meta, *src, &frame).await;
                            tx_main
                                .send(rpc::Event::Message(format!(
                                    "不正HELLO署名: id={} 切断",
                                    src
                                )))
                                .await
                                .ok();
                            dropped.insert(*src);
                        remove_indices.push(*src);
                            continue;
                        }
                    } else {
                        // 署名なし HELLO は不許可
                        let disc = protocol::Message::disconnect(current_unix_millis(), 3);
                        let frame = protocol::encode(&disc);
                        let _ = send_frame(&mut clients, &peer_meta, *src, &frame).await;
                        tx_main
                            .send(rpc::Event::Message(format!(
                                "HELLO署名なし: id={} 切断",
                                src
                            )))
                            .await
                            .ok();
                        dropped.insert(*src);
                        remove_indices.push(*src);
                        continue;
                    }

                    if *src < peer_meta.len() {
                        // ペイロード: handle + '\n' + x25519公開鍵(hex) + '\n' + ネットワーク鍵ハッシュ(hex)
                        let payload_str = String::from_utf8_lossy(&msg.payload).to_string();
                        let parts: Vec<&str> = payload_str.splitn(3, '\n').collect();
                        let peer_handle = parts[0].to_string();
                        let x25519_hex = parts.get(1).map(|s| s.to_string());
                        let peer_netkey_hex = parts.get(2).map(|s| s.to_string());
                        // ネットワーク鍵ハッシュの照合（一致しなければ別ネットワークとして切断）
                        let my_netkey = crypto::to_hex(&crypto::network_key_hash());
                        if peer_netkey_hex.as_deref() != Some(my_netkey.as_str()) {
                            let disc =
                                protocol::Message::disconnect(current_unix_millis(), 4);
                            let frame = protocol::encode(&disc);
                            let _ = send_frame(&mut clients, &peer_meta, *src, &frame).await;
                            tx_main
                                .send(rpc::Event::Message(format!(
                                    "ネットワーク鍵不一致: id={} を切断",
                                    src
                                )))
                                .await
                                .ok();
                            dropped.insert(*src);
                            remove_indices.push(*src);
                            continue;
                        }
                        let valid_handle =
                            peer_handle.starts_with('@') && peer_handle.chars().count() < 80;
                        if !valid_handle {
                            let disc = protocol::Message::disconnect(current_unix_millis(), 2);
                            let frame = protocol::encode(&disc);
                            let _ = send_frame(&mut clients, &peer_meta, *src, &frame).await;
                            tx_main
                                .send(rpc::Event::Message(format!(
                                    "不正HELLO: id={} のハンドル '{}' が不正のため切断",
                                    src, peer_handle
                                )))
                                .await
                                .ok();
                            dropped.insert(*src);
                            remove_indices.push(*src);
                        } else {
                            let own_x25519_pub = x25519_pub.clone();
                            let peer_x25519_pub = x25519_hex.and_then(|h| {
                                let b = crypto::from_hex(&h).unwrap_or_default();
                                if b.len() == 32 {
                                    Some(b)
                                } else {
                                    None
                                }
                            });
                            // HELLO で交換した X25519 鍵からホップごと
                            // トランスポートセッション鍵を導出（送信/受信別）。
                            let (transport_send, transport_recv) = match (
                                &peer_x25519_pub,
                                x25519_priv.as_ref(),
                                own_x25519_pub.as_ref(),
                            ) {
                                (Some(peer), Some(my_priv), Some(my_pub))
                                    if peer.len() == 32 =>
                                {
                                    crypto::derive_transport_keys(my_priv, my_pub, peer)
                                        .map(|(tx, rx)| (Some(tx), Some(rx)))
                                        .unwrap_or((None, None))
                                }
                                _ => (None, None),
                            };
                            let is_incoming = peer_meta[*src]
                                .as_ref()
                                .map(|m| m.is_incoming)
                                .unwrap_or(false);
                            let meta = PeerMeta {
                                public_key: pk.clone(),
                                x25519_public_key: peer_x25519_pub,
                                last_valid: true,
                                last_timestamp: msg.timestamp,
                                handle: Some(peer_handle),
                                transport_send,
                                transport_recv,
                                is_incoming,
                            };
                            peer_meta[*src] = Some(meta);

                            // 同一ピアへの二重接続（A→B と B→A の両方向）を検出・解消する。
                            // 公開鍵の大小で「どちらの方向を保持するか」を両端で対称に決定し、
                            // 結果として同じ物理リンクが1本だけ残るようにする。
                            if let (Some(local), Some(remote)) = (
                                public.as_ref().map(|v| v.as_slice()),
                                peer_meta[*src].as_ref().map(|m| m.public_key.as_slice()),
                            ) {
                                let keep_incoming = local < remote;
                                let cur_incoming = peer_meta[*src]
                                    .as_ref()
                                    .map(|m| m.is_incoming)
                                    .unwrap_or(false);
                                let dup_other_keep = peer_meta
                                    .iter()
                                    .enumerate()
                                    .any(|(j, m)| {
                                        j != *src
                                            && m.as_ref()
                                                .map(|mm| {
                                                    mm.public_key.as_slice() == remote
                                                        && mm.is_incoming == keep_incoming
                                                })
                                                .unwrap_or(false)
                                    });
                                let dup_other = peer_meta
                                    .iter()
                                    .enumerate()
                                    .any(|(j, m)| {
                                        j != *src
                                            && m.as_ref()
                                                .map(|mm| mm.public_key.as_slice() == remote)
                                                .unwrap_or(false)
                                    });
                                if cur_incoming == keep_incoming {
                                    // 保持方向の接続: 既存の非保持方向の重複を切断
                                    for j in 0..peer_meta.len() {
                                        if j == *src {
                                            continue;
                                        }
                                        let drop_it = peer_meta[j]
                                            .as_ref()
                                            .map(|mm| {
                                                mm.public_key.as_slice() == remote
                                                    && mm.is_incoming != keep_incoming
                                            })
                                            .unwrap_or(false);
                                        if drop_it {
                                            let disc = protocol::Message::disconnect(
                                                current_unix_millis(),
                                                5,
                                            );
                                            let frame = protocol::encode(&disc);
                                            let _ = send_frame(
                                                &mut clients, &peer_meta, j, &frame,
                                            )
                                            .await;
                                            tx_main
                                                .send(rpc::Event::Message(format!(
                                                    "二重接続を検出: id={} は id={} と同一ピアのため切断",
                                                    j, *src
                                                )))
                                                .await
                                                .ok();
                                            dropped.insert(j);
                                            remove_indices.push(j);
                                        }
                                    }
                                } else if dup_other && dup_other_keep {
                                    // 非保持方向で、かつ保持方向の接続が既にある → 自身を切断
                                    let disc =
                                        protocol::Message::disconnect(current_unix_millis(), 5);
                                    let frame = protocol::encode(&disc);
                                    let _ =
                                        send_frame(&mut clients, &peer_meta, *src, &frame).await;
                                    tx_main
                                        .send(rpc::Event::Message(format!(
                                            "二重接続を検出: id={} は同一ピアのため切断",
                                            *src
                                        )))
                                        .await
                                        .ok();
                                    dropped.insert(*src);
                                    remove_indices.push(*src);
                                }
                            }
                        }
                    }
                    let d = ring::digest::digest(&ring::digest::SHA256, pk);
                    let h = crypto::to_hex(d.as_ref());
                    tx_main
                        .send(rpc::Event::Message(format!(
                            "HELLO 受信: id={} 指紋={}",
                            src,
                            &h[..16]
                        )))
                        .await
                        .ok();
                } else {
                    tx_main
                        .send(rpc::Event::Message(format!(
                            "HELLO 受信: id={} (公開鍵なし)",
                            src
                        )))
                        .await
                        .ok();
                }
            } else if msg.kind == protocol::MsgKind::DM {
                // 受信表示: 本文 + 署名状態記号
                let disp = format!("{} {}", txt, signed_state);
                tx_main.send(rpc::Event::Message(disp)).await.ok();
                // 保存（受信メタ）
                let rec = crate::storage::MessageRecord {
                    ts_millis: msg.timestamp,
                    recv_ts_millis: current_unix_millis(),
                    kind: crate::storage::MsgKind::Dm,
                    from_peer_id: Some(*src),
                    to_peer_id: None,
                    handle: peer_meta
                        .get(*src)
                        .and_then(|m| m.as_ref())
                        .and_then(|m| m.handle.clone()),
                    text: txt.clone(),
                    signed_ok: Some(signed_state == "○"),
                };
                let _ = db.store_structured(&rec);
            } else {
                // 受信表示: 統一フォーマット（本文に '@handle: ' が含まれている想定）。
                // 署名状態は末尾に半角スペース+記号を付ける。
                let disp = if let Some(Some(meta)) = peer_meta.get(*src).cloned() {
                    if meta.handle.is_some() {
                        format!("{} {}", txt, signed_state)
                    } else if txt.contains(':') {
                        format!("{} {}", txt, signed_state)
                    } else {
                        format!("@{}: {} {}", src, txt, signed_state)
                    }
                } else if txt.contains(':') {
                    format!("{} {}", txt, signed_state)
                } else {
                    format!("@{}: {} {}", src, txt, signed_state)
                };
                tx_main.send(rpc::Event::Message(disp)).await.ok();
                // 保存（受信メタ）
                let rec = crate::storage::MessageRecord {
                    ts_millis: msg.timestamp,
                    recv_ts_millis: current_unix_millis(),
                    kind: crate::storage::MsgKind::Chat,
                    from_peer_id: Some(*src),
                    to_peer_id: None,
                    handle: peer_meta
                        .get(*src)
                        .and_then(|m| m.as_ref())
                        .and_then(|m| m.handle.clone()),
                    text: txt.clone(),
                    signed_ok: Some(signed_state == "○"),
                };

                let _ = db.store_structured(&rec);

                // DM は減衰せず、宛先に届いたら即中継終了
                // それ以外は減衰値を中継時にカウントアップし、最大値50で打ち止め
                let mut fwd = msg.clone();
                if fwd.kind != protocol::MsgKind::DM && fwd.attenuation < protocol::MAX_ATTENUATION
                {
                    fwd.attenuation = fwd.attenuation.saturating_add(1);
                    let frame = protocol::encode(&fwd);
                    for idx in 0..clients.len() {
                        if idx == *src {
                            continue;
                        }
                        if !should_relay_to_peer(&fwd, *src, idx) {
                            continue;
                        }

                        if let Err(e) = send_frame(&mut clients, &peer_meta, idx, &frame).await {
                            tx_main
                                .send(rpc::Event::Message(format!(
                                    "Relay write error to {}: {:?}",
                                    idx, e
                                )))
                                .await
                                .ok();
                            remove_indices.push(idx);
                        }
                    }
                }
            }

            // 不正検知: ハンドル長チェック（"@...: " のプレフィクスを解析）
            if let Some(colon) = txt.find(':') {
                let name = &txt[..colon].trim();
                if name.starts_with('@') {
                    let count = name.chars().count();
                    if count >= 80 {
                        // 切断: 理由ID=1（ハンドル長超過）
                        let reason_id: u32 = 1;
                        if *src < clients.len() {
                            let disc =
                                protocol::Message::disconnect(current_unix_millis(), reason_id);
                            let frame = protocol::encode(&disc);
                            let _ = send_frame(&mut clients, &peer_meta, *src, &frame).await;
                        }
                        tx_main
                            .send(rpc::Event::Message(format!(
                                "不正検知: id={} のハンドル長({})が制限超過のため切断",
                                src, count
                            )))
                            .await
                            .ok();
                        dropped.insert(*src);
                        remove_indices.push(*src);
                        // 次のメッセージ処理へ
                        continue;
                    }
                }
            }
        }

        // 削除
        remove_indices.sort_unstable();
        remove_indices.dedup();
        for i in remove_indices.into_iter().rev() {
            clients.remove(i);
            decoders.remove(i);
            peer_meta.remove(i);
            raw_bufs.remove(i);
        }

        // アイドル時（コマンド/受信/受け入れいずれも無し）にも他タスクへ譲りつつ、
        // CPU を独占しないよう軽くスリープする（受け入れは別タスクが捌くので問題なし）。
        sleep(Duration::from_millis(10)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_probability_is_monotonic() {
        assert_eq!(relay_probability_percent(0), 100);
        assert_eq!(relay_probability_percent(FULL_RELAY_ATTENUATION), 100);
        assert_eq!(relay_probability_percent(protocol::MAX_ATTENUATION), 0);
        assert!(relay_probability_percent(20) < relay_probability_percent(10));
    }

    #[test]
    fn duplicate_detection_ignores_attenuation() {
        let mut seen_messages: HashSet<[u8; 32]> = HashSet::new();
        let mut seen_order: VecDeque<[u8; 32]> = VecDeque::new();
        let mut msg = protocol::Message::chat("hello", 12345);
        msg.public_key = Some(vec![7; 32]);
        msg.signature = Some(vec![9; 64]);
        assert!(!is_duplicate_message(
            &msg,
            &mut seen_messages,
            &mut seen_order
        ));

        let mut replay = msg.clone();
        replay.attenuation = 40;
        assert!(is_duplicate_message(
            &replay,
            &mut seen_messages,
            &mut seen_order
        ));
    }

    #[test]
    fn signed_dm_payload_is_binary_safe() {
        let keys = crypto::generate_ed25519_keypair().unwrap();
        let (recipient_priv, recipient_pub) = crypto::generate_x25519_keypair().unwrap();
        let (sender_priv, _sender_pub) = crypto::generate_x25519_keypair().unwrap();
        let plain = "@alice: こんにちは";
        let msg = build_signed_dm(
            plain,
            &keys.pkcs8,
            &keys.public,
            &recipient_pub,
            &sender_priv,
        )
        .unwrap();

        assert_eq!(msg.kind, protocol::MsgKind::DM);
        let decrypted = crypto::decrypt_dm_payload(&recipient_priv, &msg.payload).unwrap();
        assert_eq!(String::from_utf8_lossy(&decrypted), plain);
    }
}
