use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender};
use std::{thread, time::Duration};
use crate::{build_signed_chat, build_signed_dm, build_signed_hello, config, crypto, current_unix_millis, protocol,rpc::Command};

pub fn network_handler(tx_main: Sender<String>, rx_thread: Receiver<Command>) {
    tx_main.send("ネットワークスレッド開始".to_string()).ok();
    let mut listener: Option<TcpListener> = None;
    let mut clients: Vec<TcpStream> = Vec::new();
    // 各 client ごとのデコーダ
    let mut decoders: Vec<protocol::Decoder> = Vec::new();
    #[derive(Clone, Debug)]
    struct PeerMeta { public_key: Vec<u8>, last_valid: bool, last_timestamp: u64, handle: Option<String> }
    let mut peer_meta: Vec<Option<PeerMeta>> = Vec::new();
    let mut buf = [0u8; 2048];
    // ハンドル（必須）
    let mut handle: String = config::get_value("user.handle")
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();

    // 署名用鍵を読む (存在しなければ None)
    let mut pkcs8: Option<Vec<u8>> = None;
    let mut public: Option<Vec<u8>> = None;
    // 起動時に読み込み ( /init 後は再起動で有効 )。将来ホットリロードするなら /reload 等追加。
    if let (Some(pk_hex), Some(pub_hex)) = (
        config::get_value("key.pkcs8").and_then(|v| v.as_str().map(|s| s.to_string())),
        config::get_value("key.public").and_then(|v| v.as_str().map(|s| s.to_string()))
    ) {
        let pk_bytes = crypto::from_hex(&pk_hex).unwrap_or_default();
        let pub_bytes = crypto::from_hex(&pub_hex).unwrap_or_default();
        if !pk_bytes.is_empty() && !pub_bytes.is_empty() { pkcs8 = Some(pk_bytes); public = Some(pub_bytes); }
    }

    loop {
        // コマンド処理: drain できるだけ読む
        while let Ok(cmd) = rx_thread.try_recv() {
            match cmd {
                Command::Shutdown => { tx_main.send("Shutdown を受信 -> 終了します".to_string()).ok(); return; }
                Command::Open(port) => {
                    if listener.is_some() {
                        tx_main.send("既に待受中（/open は同時に1つまで）".into()).ok();
                    } else {
                        match TcpListener::bind(format!("127.0.0.1:{}", port)) {
                            Ok(l) => { 
                                l.set_nonblocking(true).ok(); 
                                listener = Some(l); 
                                let addr = format!("127.0.0.1:{}", port);
                                let tok = crypto::encrypt_conninfo_to_hex(&addr).unwrap_or_else(|_| "?".into());
                                tx_main.send(format!("待受開始 (token={})", tok)).ok(); 
                            }
                            Err(e) => { tx_main.send(format!("バインドエラー: {:?}", e)).ok(); }
                        }
                    }
                }
                Command::Connect(token) => {
                    // トークンのみ受け付け。復号失敗ならエラー
                    let target = match crypto::decrypt_conninfo_from_hex(&token) { Ok(s) => s, Err(e) => { tx_main.send(format!("接続トークンの復号エラー: {}", e)).ok(); continue; } };
                    match TcpStream::connect(&target) {
                        Ok(s) => {
                            let s = s; s.set_nonblocking(true).ok();
                            clients.push(s);
                            decoders.push(protocol::Decoder::new());
                            peer_meta.push(None);
                            let id = clients.len()-1;
                            // 接続直後に公開鍵ハンドシェイクを送信
                            if let (Some(pubk), Some(pk)) = (public.as_ref(), pkcs8.as_ref()) {
                                if let Some(hello) = build_signed_hello(&handle, pk, pubk) {
                                    let frame = protocol::encode(&hello);
                                    let _ = clients[id].write_all(&frame);
                                }
                            }
                            tx_main.send(format!("接続完了 (token={}) id={}", token, id)).ok();
                        }
                        Err(e) => { tx_main.send(format!("接続エラー (token={}): {:?}", token, e)).ok(); }
                    }
                }
                Command::Close => {
                    if listener.is_some() { listener = None; tx_main.send("待受を終了しました".into()).ok(); } else { tx_main.send("待受は起動していません".into()).ok(); }
                }
                Command::Disconnect(rest) => {
                    if let Ok(id) = rest.trim().parse::<usize>() {
                        if id < clients.len() { clients.remove(id); decoders.remove(id); peer_meta.remove(id); tx_main.send(format!("切断しました id {}", id)).ok(); }
                        else { tx_main.send(format!("切断: 不正な id {}", id)).ok(); }
                    } else { tx_main.send(format!("切断: 解析エラー '{}': 数値を指定してください", rest)).ok(); }
                }
                Command::PeerList => {
                    let mut lines = Vec::new();
                    lines.push(format!("ピア数={} 待受={}", clients.len(), listener.is_some()));
                    for (i, c) in clients.iter().enumerate() {
                        let addr = c.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into());
                        let tok = crypto::encrypt_conninfo_to_hex(&addr).unwrap_or_else(|_| "?".into());
                        let fp = peer_meta.get(i).and_then(|m| m.as_ref()).map(|m| {
                            let d = ring::digest::digest(&ring::digest::SHA256, &m.public_key);
                            let h = crypto::to_hex(d.as_ref());
                            format!("指紋={}", &h[..16])
                        }).unwrap_or_else(|| "指紋=?".into());
                        lines.push(format!("id={} token={} {}", i, tok, fp));
                    }
                    tx_main.send(lines.join("\n")).ok();
                }
                Command::Certs => {
                    let mut lines = vec!["証明書:".to_string()];
                    for (i, meta) in peer_meta.iter().enumerate() {
                        match meta {
                            Some(m) => {
                                let d = ring::digest::digest(&ring::digest::SHA256, &m.public_key);
                                let h = crypto::to_hex(d.as_ref());
                                lines.push(format!("id={} 有効={} ts={} 公開鍵長={} 指紋={}", i, m.last_valid, m.last_timestamp, m.public_key.len(), &h[..32]));
                            }
                            None => lines.push(format!("id={} <鍵なし>", i)),
                        }
                    }
                    tx_main.send(lines.join("\n")).ok();
                }
                Command::Handle(name) => {
                    if name.starts_with('@') && name.chars().count() < 80 {
                        handle = name.clone();
                        tx_main.send(format!("ハンドル適用: {}", handle)).ok();
                    } else {
                        tx_main.send("/handle は @から始まり80文字未満".into()).ok();
                    }
                }
                Command::Chat(rest) => {
                    // 送信メッセージをプロトコルフレーム化
                    if let (Some(ref pk), Some(ref pubk)) = (pkcs8.as_ref(), public.as_ref()) {
                        // 送信本文にハンドルをプレーンで含める
                        let body = format!("{}: {}", handle, rest);
                        if let Some(m) = build_signed_chat(&body, pk, pubk) {
                            let frame = protocol::encode(&m);
                            let mut remove = Vec::new();
                            for (i, c) in clients.iter_mut().enumerate() {
                                if let Err(e) = c.write_all(&frame) { tx_main.send(format!("送信エラー {}: {:?}", i, e)).ok(); remove.push(i); }
                            }
                            // 保存（送信メタ）
                            let rec = crate::storage::MessageRecord {
                                ts_millis: m.timestamp,
                                recv_ts_millis: crate::current_unix_millis(),
                                kind: crate::storage::MsgKind::Chat,
                                from_peer_id: None,
                                to_peer_id: None,
                                handle: Some(handle.clone()),
                                text: body,
                                signed_ok: Some(true),
                            };
                            let _ = crate::storage::store_structured(&rec);
                            for i in remove.into_iter().rev() { clients.remove(i); decoders.remove(i); }
                        } else { tx_main.send("署名生成失敗".into()).ok(); }
                    } else {
                        tx_main.send("鍵未生成 (/init を先に実行)".into()).ok();
                    }
                }
                Command::DM(to_str, msg_body) => {
                    // /dm <to_id> <message>
                    if let Ok(target) = to_str.parse::<usize>() {
                        if target < clients.len() {
                            if let (Some(ref pk), Some(ref pubk)) = (pkcs8.as_ref(), public.as_ref()) {
                                let body = format!("{}: {}", handle, msg_body);
                                if let Some(m) = build_signed_dm(&body, pk, pubk) {
                                    let frame = protocol::encode(&m);
                                    if let Err(e) = clients[target].write_all(&frame) { tx_main.send(format!("DM送信エラー {}: {:?}", target, e)).ok(); }
                                    // 保存（送信メタ）
                                    let rec = crate::storage::MessageRecord {
                                        ts_millis: m.timestamp,
                                        recv_ts_millis: crate::current_unix_millis(),
                                        kind: crate::storage::MsgKind::Dm,
                                        from_peer_id: None,
                                        to_peer_id: Some(target),
                                        handle: Some(handle.clone()),
                                        text: body,
                                        signed_ok: Some(true),
                                    };
                                    let _ = crate::storage::store_structured(&rec);
                                } else { tx_main.send("DM署名生成失敗".into()).ok(); }
                            } else { tx_main.send("鍵未生成 (/init を先に実行)".into()).ok(); }
                        } else {
                            tx_main.send(format!("DM 宛先 id {} が範囲外です", target)).ok();
                        }
                    } else {
                        tx_main.send(format!("不正な DM 宛先: {}", to_str)).ok();
                    }
                }
            }
        }

        // accept
        if let Some(l) = &listener {
            loop {
                match l.accept() {
                    Ok((s, peer)) => {
                        let s = s; s.set_nonblocking(true).ok();
                        clients.push(s);
                        decoders.push(protocol::Decoder::new());
                        peer_meta.push(None);
                        // 受け入れ側も公開鍵を送信
                        let id = clients.len()-1;
                        if let (Some(pubk), Some(pk)) = (public.as_ref(), pkcs8.as_ref()) {
                            if let Some(hello) = build_signed_hello(&handle, pk, pubk) {
                                let frame = protocol::encode(&hello);
                                let _ = clients[id].write_all(&frame);
                            }
                        }
                        let token = crypto::encrypt_conninfo_to_hex(&peer.to_string()).unwrap_or_else(|_| "?".to_string());
                        tx_main.send(format!("接続受入 (token={}) id={}", token, id)).ok();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => { tx_main.send(format!("受け入れエラー: {:?}", e)).ok(); break; }
                }
            }
        }

        // 読み取り (バイナリプロトコル優先)
        let mut received_frames: Vec<(usize, protocol::Message)> = Vec::new();
        let mut remove_indices: Vec<usize> = Vec::new();
        for (idx, c) in clients.iter_mut().enumerate() {
            match c.read(&mut buf) {
                Ok(0) => { tx_main.send(format!("クライアント {} が切断しました", idx)).ok(); remove_indices.push(idx); }
                Ok(n) => { if n>0 { decoders[idx].feed(&buf[..n]); if let Ok(mut msgs) = decoders[idx].drain() { for m in msgs.drain(..) { received_frames.push((idx, m)); } } } }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => { tx_main.send(format!("受信エラー {}: {:?}", idx, e)).ok(); remove_indices.push(idx); }
            }
        }

        // 中継と表示 + 署名検証
        for (src, msg) in received_frames.iter() {
            // テキスト復号/デコード
            let txt = if msg.kind == protocol::MsgKind::DM {
                match crypto::decrypt_dm_payload(&msg.payload) {
                    Ok(p) => String::from_utf8_lossy(&p).to_string(),
                    Err(_) => "<DM復号エラー>".to_string(),
                }
            } else {
                String::from_utf8_lossy(&msg.payload).to_string()
            };
            let mut signed_state = if msg.signature.is_some() { "○" } else { "・" };
            let mut good = true;
            if let (Some(sig), Some(pk)) = (msg.signature.as_ref(), msg.public_key.as_ref()) {
                // 検証 (public_key & signature は署名対象外領域)
                let minimal = protocol::Message { version: msg.version, kind: msg.kind, payload: msg.payload.clone(), timestamp: msg.timestamp, public_key: None, signature: None };
                let data = protocol::signing_bytes(&minimal);
                if crypto::verify_ed25519(&data, sig, pk).is_err() { signed_state = "×"; good = false; }
                // メタ更新（既存のハンドル情報は維持）
                if *src < peer_meta.len() {
                    let existing_handle = peer_meta[*src].as_ref().and_then(|m| m.handle.clone());
                    peer_meta[*src] = Some(PeerMeta { public_key: pk.clone(), last_valid: good, last_timestamp: msg.timestamp, handle: existing_handle });
                }
            }
            if msg.kind == protocol::MsgKind::DISCONNECT {
                let reason = protocol::disconnect_reason_id(msg).unwrap_or(0);
                tx_main.send(format!("相手から切断通知 id={} reason={}", src, reason)).ok();
                remove_indices.push(*src);
            } else if msg.kind == protocol::MsgKind::HELLO {
                // 相手の公開鍵が含まれていれば保存
                if let Some(pk) = msg.public_key.as_ref() {
                    // HELLO 自体の署名検証
                    let minimal = protocol::Message { version: msg.version, kind: msg.kind, payload: msg.payload.clone(), timestamp: msg.timestamp, public_key: None, signature: None };
                    let data = protocol::signing_bytes(&minimal);
                    if let Some(sig) = msg.signature.as_ref() {
                        if crypto::verify_ed25519(&data, sig, pk).is_err() {
                            // 理由ID=3: HELLO署名不正
                            let disc = protocol::Message::disconnect(current_unix_millis(), 3);
                            let frame = protocol::encode(&disc);
                            let _ = clients[*src].write_all(&frame);
                            tx_main.send(format!("不正HELLO署名: id={} 切断", src)).ok();
                            remove_indices.push(*src);
                            continue;
                        }
                    } else {
                        // 署名なし HELLO は不許可
                        let disc = protocol::Message::disconnect(current_unix_millis(), 3);
                        let frame = protocol::encode(&disc);
                        let _ = clients[*src].write_all(&frame);
                        tx_main.send(format!("HELLO署名なし: id={} 切断", src)).ok();
                        remove_indices.push(*src);
                        continue;
                    }

                    if *src < peer_meta.len() {
                        let peer_handle = String::from_utf8_lossy(&msg.payload).to_string();
                        let valid_handle = peer_handle.starts_with('@') && peer_handle.chars().count() < 80;
                        if !valid_handle {
                            let disc = protocol::Message::disconnect(current_unix_millis(), 2);
                            let frame = protocol::encode(&disc);
                            let _ = clients[*src].write_all(&frame);
                            tx_main.send(format!("不正HELLO: id={} のハンドル '{}' が不正のため切断", src, peer_handle)).ok();
                            remove_indices.push(*src);
                        } else {
                            let meta = PeerMeta { public_key: pk.clone(), last_valid: true, last_timestamp: msg.timestamp, handle: Some(peer_handle) };
                            peer_meta[*src] = Some(meta);
                        }
                    }
                    let d = ring::digest::digest(&ring::digest::SHA256, pk);
                    let h = crypto::to_hex(d.as_ref());
                    tx_main.send(format!("HELLO 受信: id={} 指紋={}", src, &h[..16])).ok();
                } else {
                    tx_main.send(format!("HELLO 受信: id={} (公開鍵なし)", src)).ok();
                }
            } else if msg.kind == protocol::MsgKind::DM {
                // 受信表示: 本文 + 署名状態記号
                let disp = format!("{} {}", txt, signed_state);
                tx_main.send(disp).ok();
                // 保存（受信メタ）
                let rec = crate::storage::MessageRecord {
                    ts_millis: msg.timestamp,
                    recv_ts_millis: crate::current_unix_millis(),
                    kind: crate::storage::MsgKind::Dm,
                    from_peer_id: Some(*src),
                    to_peer_id: None,
                    handle: peer_meta.get(*src).and_then(|m| m.as_ref()).and_then(|m| m.handle.clone()),
                    text: txt.clone(),
                    signed_ok: Some(signed_state == "○"),
                };
                let _ = crate::storage::store_structured(&rec);
            } else {
                // 受信表示: 統一フォーマット（本文に '@handle: ' が含まれている想定）。
                // 署名状態は末尾に半角スペース+記号を付ける。
                let disp = if let Some(Some(meta)) = peer_meta.get(*src).cloned() {
                    if meta.handle.is_some() { format!("{} {}", txt, signed_state) } else if txt.contains(':') { format!("{} {}", txt, signed_state) } else { format!("@{}: {} {}", src, txt, signed_state) }
                } else if txt.contains(':') { format!("{} {}", txt, signed_state) } else { format!("@{}: {} {}", src, txt, signed_state) };
                tx_main.send(disp).ok();
                // 保存（受信メタ）
                let rec = crate::storage::MessageRecord {
                    ts_millis: msg.timestamp,
                    recv_ts_millis: crate::current_unix_millis(),
                    kind: crate::storage::MsgKind::Chat,
                    from_peer_id: Some(*src),
                    to_peer_id: None,
                    handle: peer_meta.get(*src).and_then(|m| m.as_ref()).and_then(|m| m.handle.clone()),
                    text: txt.clone(),
                    signed_ok: Some(signed_state == "○"),
                };
                let _ = crate::storage::store_structured(&rec);
                let frame = protocol::encode(msg);
                for (idx, c) in clients.iter_mut().enumerate() {
                    if idx == *src { continue; }
                    if let Err(e) = c.write_all(&frame) { tx_main.send(format!("Relay write error to {}: {:?}", idx, e)).ok(); remove_indices.push(idx); }
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
                            let disc = protocol::Message::disconnect(current_unix_millis(), reason_id);
                            let frame = protocol::encode(&disc);
                            let _ = clients[*src].write_all(&frame);
                        }
                        tx_main.send(format!("不正検知: id={} のハンドル長({})が制限超過のため切断", src, count)).ok();
                        remove_indices.push(*src);
                        // 次のメッセージ処理へ
                        continue;
                    }
                }
            }
        }

        // 削除
    remove_indices.sort_unstable(); remove_indices.dedup();
    for i in remove_indices.into_iter().rev() { clients.remove(i); decoders.remove(i); peer_meta.remove(i); }

        thread::sleep(Duration::from_millis(15));
    }
}

