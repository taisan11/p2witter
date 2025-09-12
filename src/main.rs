use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self};
use std::time::Duration;
mod protocol;
mod config;
mod crypto;

fn current_unix_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

// 署名付きチャット送信 (全体ブロードキャスト) - 鍵必須
fn build_signed_chat(text: &str, pkcs8: &[u8], pubk: &[u8]) -> Option<protocol::Message> {
    let mut m = protocol::Message::chat(text, current_unix_millis());
    if let Ok(sig) = crypto::sign_ed25519(&protocol::signing_bytes(&m), pkcs8) { m = m.with_key_sig(pubk.to_vec(), sig); Some(m) } else { None }
}
// 署名付きDM
fn build_signed_dm(text: &str, pkcs8: &[u8], pubk: &[u8]) -> Option<protocol::Message> {
    let mut m = protocol::Message::dm(text, current_unix_millis());
    if let Ok(sig) = crypto::sign_ed25519(&protocol::signing_bytes(&m), pkcs8) { m = m.with_key_sig(pubk.to_vec(), sig); Some(m) } else { None }
}

fn main() {
    // メインスレッドと通信するためのチャンネル
    let (tx_to_main, rx_from_threads) = mpsc::channel::<String>();

    let mut active_thread_tx: Option<Sender<String>> = None;
    let mut active_thread_handle: Option<thread::JoinHandle<()>> = None; // JoinHandle 型は fully qualified で利用
    
    // config 初期化: なければデフォルト生成
    if let Err(e) = config::init_config_path("./config.toml") {
        eprintln!("Failed to init config: {e}");
    }

    loop {
        // 他スレッドからのメッセージを継続的にチェック・表示
        let mut has_new_messages = false;
        while let Ok(msg) = rx_from_threads.try_recv() {
            if !has_new_messages { has_new_messages = true; }
            println!("{}", msg);
        }
        
        if has_new_messages {
            print!("> ");
            io::stdout().flush().unwrap();
        } else {
            print!("> ");
            io::stdout().flush().unwrap();
        }
        
        // 入力待機中も定期的にメッセージをチェック
        let (tx_input, rx_input) = mpsc::channel();
        let tx_input_clone = tx_input.clone();
        thread::spawn(move || {
            let mut input = String::new();
            io::stdin().read_line(&mut input).ok();
            tx_input_clone.send(input).ok();
        });
        
        // 入力待機とメッセージ受信を並行処理
        let input = loop {
            // メッセージ受信チェック
            while let Ok(msg) = rx_from_threads.try_recv() {
                // プロンプト行を上書きクリア（改行を増やさない）
                print!("\r{}\r", " ".repeat(50));
                println!("{}", msg);
                print!("> ");
                io::stdout().flush().unwrap();
            }
            
            // 入力チェック
            if let Ok(input) = rx_input.try_recv() {
                break input;
            }
            
            thread::sleep(Duration::from_millis(50));
        };
        let input = input.trim().to_string();
        let parts: Vec<String> = input
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        match parts.get(0).map(|s| s.as_str()) {
            Some("/open") => {
                if let Some(port) = parts.get(1) {
                    if active_thread_tx.is_none() {
                        let tx_main = tx_to_main.clone();
                        let (tx_thread, rx_thread) = mpsc::channel();
                        let handle = thread::spawn(move || { run_network(tx_main, rx_thread); });
                        active_thread_tx = Some(tx_thread);
                        active_thread_handle = Some(handle);
                    }
                    if let Some(ref tx) = active_thread_tx { tx.send(format!("/open {}", port)).ok(); }
                } else { println!("Usage: /open <port>"); }
            }
            Some("/connect") => {
                if let Some(addr) = parts.get(1) {
                    if active_thread_tx.is_none() {
                        let tx_main = tx_to_main.clone();
                        let (tx_thread, rx_thread) = mpsc::channel();
                        let handle = thread::spawn(move || { run_network(tx_main, rx_thread); });
                        active_thread_tx = Some(tx_thread);
                        active_thread_handle = Some(handle);
                    }
                    if let Some(ref tx) = active_thread_tx { tx.send(format!("/connect {}", addr)).ok(); }
                } else { println!("Usage: /connect <addr:port>"); }
            }
            Some("/exit") => {
                println!("Exiting...");
                
                // アクティブなスレッドに終了を通知
                if let Some(ref tx) = active_thread_tx {
                    tx.send("/exit".to_string()).ok();
                    drop(active_thread_tx.take()); // チャンネルをクローズ
                }
                
                // スレッドの終了を待機
                if let Some(handle) = active_thread_handle.take() {
                    println!("Waiting for threads to finish...");
                    handle.join().ok();
                }
                
                println!("All threads finished. Goodbye!");
                break;
            }
            Some("/debug") => { println!("{:?}", config::get_value("hoi")); }
            Some("/init") => {
                // 鍵生成して config に保存 (上書き)
                match crypto::generate_ed25519_keypair() {
                    Ok(k) => {
                        config::upsert_value_and_save("key.pkcs8", toml::Value::String(crypto::to_hex(&k.pkcs8))).ok();
                        config::upsert_value_and_save("key.public", toml::Value::String(crypto::to_hex(&k.public))).ok();
                        println!("鍵生成 & 保存完了 (public={} bytes)", k.public.len());
                    }
                    Err(e) => eprintln!("鍵生成失敗: {e}"),
                }
            }
            Some("/peers") => {
                if let Some(ref tx) = active_thread_tx { tx.send("/peers".to_string()).ok(); }
                else { println!("No network thread. Use /server or /client first"); }
            }
            Some("/close") => {
                if let Some(ref tx) = active_thread_tx { tx.send("/close".to_string()).ok(); }
                else { println!("No network thread. Use /open first"); }
            }
            Some("/disconnect") => {
                if parts.len() < 2 { println!("Usage: /disconnect <id>"); continue; }
                if let Some(ref tx) = active_thread_tx { tx.send(format!("/disconnect {}", parts[1])).ok(); }
                else { println!("No network thread. Use /connect or /open first"); }
            }
            Some("/dm") => {
                if parts.len() < 3 { println!("Usage: /dm <to_id> <message>"); continue; }
                let to_id = &parts[1];
                let value = parts[2..].join(" ");
                if let Some(ref tx) = active_thread_tx { tx.send(format!("/dm {} {}", to_id, value)).ok(); } else { println!("No network thread. Use /server or /client first"); }
            }
            Some(other) => {
                // コマンドとして既知でない → 通常メッセージ扱い
                if other.starts_with('/') { println!("Unknown command: {}", other); }
                else if let Some(ref tx) = active_thread_tx { tx.send(format!("/msg {}", input)).ok(); }
                else { println!("No network thread. Use /server or /client first"); }
            }
            None => { /* ignore */ }
        }
    }
}

fn run_network(tx_main: Sender<String>, rx_thread: Receiver<String>) {
    tx_main.send("network thread started".to_string()).ok();
    let mut listener: Option<TcpListener> = None;
    let mut clients: Vec<TcpStream> = Vec::new();
    // 各 client ごとのデコーダ
    let mut decoders: Vec<protocol::Decoder> = Vec::new();
    let mut buf = [0u8; 2048];

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
            if cmd == "/exit" { tx_main.send("/exit received -> shutting down".to_string()).ok(); return; }
            if let Some(rest) = cmd.strip_prefix("/open ") {
                if listener.is_some() {
                    tx_main.send("already listening (only one /open allowed)".into()).ok();
                } else {
                    match TcpListener::bind(format!("127.0.0.1:{}", rest)) {
                        Ok(l) => { l.set_nonblocking(true).ok(); listener = Some(l); tx_main.send(format!("Listening on 127.0.0.1:{}", rest)).ok(); }
                        Err(e) => { tx_main.send(format!("Bind error: {:?}", e)).ok(); }
                    }
                }
            } else if let Some(rest) = cmd.strip_prefix("/connect ") {
                match TcpStream::connect(rest) {
                    Ok(s) => { let s=s; s.set_nonblocking(true).ok(); clients.push(s); decoders.push(protocol::Decoder::new()); tx_main.send(format!("Connected to {} (id={})", rest, clients.len()-1)).ok(); }
                    Err(e) => { tx_main.send(format!("Connect error ({}): {:?}", rest, e)).ok(); }
                }
            } else if cmd == "/close" {
                if listener.is_some() { listener = None; tx_main.send("listener closed".into()).ok(); } else { tx_main.send("no active listener".into()).ok(); }
            } else if let Some(rest) = cmd.strip_prefix("/disconnect ") {
                if let Ok(id) = rest.trim().parse::<usize>() {
                    if id < clients.len() { clients.remove(id); decoders.remove(id); tx_main.send(format!("disconnected id {}", id)).ok(); }
                    else { tx_main.send(format!("disconnect: invalid id {}", id)).ok(); }
                } else { tx_main.send(format!("disconnect: parse error '{}': expected number", rest)).ok(); }
            } else if cmd == "/peers" {
                let mut lines = Vec::new();
                lines.push(format!("peers total={} listening={}", clients.len(), listener.is_some()));
                for (i, c) in clients.iter().enumerate() {
                    let addr = c.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into());
                    lines.push(format!("id={} addr={}", i, addr));
                }
                tx_main.send(lines.join("\n")).ok();
            } else if let Some(rest) = cmd.strip_prefix("/msg ") {
                // 送信メッセージをプロトコルフレーム化
                if let (Some(ref pk), Some(ref pubk)) = (pkcs8.as_ref(), public.as_ref()) {
                    if let Some(m) = build_signed_chat(rest, pk, pubk) {
                        let frame = protocol::encode(&m);
                        let mut remove = Vec::new();
                        for (i, c) in clients.iter_mut().enumerate() {
                            if let Err(e) = c.write_all(&frame) { tx_main.send(format!("Write error to {}: {:?}", i, e)).ok(); remove.push(i); }
                        }
                        for i in remove.into_iter().rev() { clients.remove(i); decoders.remove(i); }
                    } else { tx_main.send("署名生成失敗".into()).ok(); }
                } else {
                    tx_main.send("鍵未生成 (/init を先に実行)".into()).ok();
                }
            } else if let Some(rest) = cmd.strip_prefix("/dm ") {
                // /dm <to_id> <message>
                let mut iter = rest.splitn(2, ' ');
                let to = iter.next().unwrap_or("");
                let msg_body = iter.next().unwrap_or("");
                if let Ok(target) = to.parse::<usize>() {
                    if target < clients.len() {
                        if let (Some(ref pk), Some(ref pubk)) = (pkcs8.as_ref(), public.as_ref()) {
                            if let Some(m) = build_signed_dm(msg_body, pk, pubk) {
                                let frame = protocol::encode(&m);
                                if let Err(e) = clients[target].write_all(&frame) { tx_main.send(format!("DM write error to {}: {:?}", target, e)).ok(); }
                            } else { tx_main.send("DM署名生成失敗".into()).ok(); }
                        } else { tx_main.send("鍵未生成 (/init を先に実行)".into()).ok(); }
                    } else {
                        tx_main.send(format!("DM target id {} out of range", target)).ok();
                    }
                } else {
                    tx_main.send(format!("Invalid dm target: {}", to)).ok();
                }
            } else if !cmd.is_empty() {
                // 旧テキスト互換は廃止: 非コマンド入力は /msg 側で処理される
            }
        }

        // accept
        if let Some(l) = &listener {
            loop {
                match l.accept() {
                    Ok((s, peer)) => { let s=s; s.set_nonblocking(true).ok(); clients.push(s); decoders.push(protocol::Decoder::new()); tx_main.send(format!("Accepted {} (id={})", peer, clients.len()-1)).ok(); }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => { tx_main.send(format!("Accept error: {:?}", e)).ok(); break; }
                }
            }
        }

        // 読み取り (バイナリプロトコル優先)
        let mut received_frames: Vec<(usize, protocol::Message)> = Vec::new();
        let mut remove_indices: Vec<usize> = Vec::new();
        for (idx, c) in clients.iter_mut().enumerate() {
            match c.read(&mut buf) {
                Ok(0) => { tx_main.send(format!("Client {} closed", idx)).ok(); remove_indices.push(idx); }
                Ok(n) => { if n>0 { decoders[idx].feed(&buf[..n]); if let Ok(mut msgs) = decoders[idx].drain() { for m in msgs.drain(..) { received_frames.push((idx, m)); } } } }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => { tx_main.send(format!("Read error {}: {:?}", idx, e)).ok(); remove_indices.push(idx); }
            }
        }

        // 中継と表示 + 署名検証
        for (src, msg) in received_frames.iter() {
            let txt = String::from_utf8_lossy(&msg.payload);
            let mut signed_state = if msg.signature.is_some() { "signed" } else { "plain" };
            if let (Some(sig), Some(pk)) = (msg.signature.as_ref(), msg.public_key.as_ref()) {
                // 検証
                let minimal = protocol::Message { version: msg.version, kind: msg.kind, payload: msg.payload.clone(), timestamp: msg.timestamp, public_key: None, signature: None };
                let data = protocol::signing_bytes(&minimal);
                if crypto::verify_ed25519(&data, sig, pk).is_err() { signed_state = "bad-signature"; }
            }
            if msg.kind == protocol::MsgKind::DM {
                tx_main.send(format!("DM!! from:{} {} [{}]", src, txt, signed_state)).ok();
            } else {
                tx_main.send(format!("受信(id={}): {} [{}]", src, txt, signed_state)).ok();
                let frame = protocol::encode(msg);
                for (idx, c) in clients.iter_mut().enumerate() {
                    if idx == *src { continue; }
                    if let Err(e) = c.write_all(&frame) { tx_main.send(format!("Relay write error to {}: {:?}", idx, e)).ok(); remove_indices.push(idx); }
                }
            }
        }

        // 削除
        remove_indices.sort_unstable(); remove_indices.dedup();
    for i in remove_indices.into_iter().rev() { clients.remove(i); decoders.remove(i); }

        thread::sleep(Duration::from_millis(15));
    }
}
