use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self};
use std::time::Duration;
mod protocol;

fn main() {
    // メインスレッドと通信するためのチャンネル
    let (tx_to_main, rx_from_threads) = mpsc::channel::<String>();
    
    let mut active_thread_tx: Option<Sender<String>> = None;
    let mut active_thread_handle: Option<thread::JoinHandle<()>> = None; // JoinHandle 型は fully qualified で利用
    
    loop {
        // 他スレッドからのメッセージを継続的にチェック・表示
        let mut has_new_messages = false;
        while let Ok(msg) = rx_from_threads.try_recv() {
            if !has_new_messages { has_new_messages = true; }
            println!("{}", msg);
        }
        
        if has_new_messages {
            // メッセージ表示後にプロンプトを再表示
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
            Some("/server") => {
                if let Some(port) = parts.get(1) {
                    // ネットワークスレッド未起動なら起動
                    if active_thread_tx.is_none() {
                        let tx_main = tx_to_main.clone();
                        let (tx_thread, rx_thread) = mpsc::channel();
                        let handle = thread::spawn(move || { run_network(tx_main, rx_thread); });
                        active_thread_tx = Some(tx_thread);
                        active_thread_handle = Some(handle);
                    }
                    if let Some(ref tx) = active_thread_tx { tx.send(format!("/server {}", port)).ok(); }
                } else { println!("Usage: /server <port>"); }
            }
            Some("/client") => {
                if let Some(addr) = parts.get(1) {
                    if active_thread_tx.is_none() {
                        let tx_main = tx_to_main.clone();
                        let (tx_thread, rx_thread) = mpsc::channel();
                        let handle = thread::spawn(move || { run_network(tx_main, rx_thread); });
                        active_thread_tx = Some(tx_thread);
                        active_thread_handle = Some(handle);
                    }
                    if let Some(ref tx) = active_thread_tx { tx.send(format!("/client {}", addr)).ok(); }
                } else { println!("Usage: /client <addr:port>"); }
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
            Some(cmd) => {
                // その他はネットワークスレッドへメッセージとして送信（ブロードキャスト）
                if let Some(ref tx) = active_thread_tx { tx.send(cmd.to_string()).ok(); }
                else { println!("No network thread. Use /server or /client first"); }
            }
            None => { /* 空行は無視 */ }
        }
    }
}

fn run_network(tx_main: Sender<String>, rx_thread: Receiver<String>) {
    tx_main.send("network thread started".to_string()).ok();
    let mut listener: Option<TcpListener> = None;
    let mut clients: Vec<TcpStream> = Vec::new();
    let mut buf = [0u8; 1024];

    loop {
        // コマンド処理: drain できるだけ読む
        while let Ok(cmd) = rx_thread.try_recv() {
            if cmd == "/exit" { tx_main.send("/exit received -> shutting down".to_string()).ok(); return; }
            if let Some(rest) = cmd.strip_prefix("/server ") {
                // リスナー開始/再設定
                match TcpListener::bind(format!("127.0.0.1:{}", rest)) {
                    Ok(l) => { l.set_nonblocking(true).ok(); listener = Some(l); tx_main.send(format!("Listening on 127.0.0.1:{}", rest)).ok(); }
                    Err(e) => { tx_main.send(format!("Bind error: {:?}", e)).ok(); }
                }
            } else if let Some(rest) = cmd.strip_prefix("/client ") {
                match TcpStream::connect(rest) {
                    Ok(s) => { let s=s; s.set_nonblocking(true).ok(); clients.push(s); tx_main.send(format!("Connected to {} (id={})", rest, clients.len()-1)).ok(); }
                    Err(e) => { tx_main.send(format!("Connect error ({}): {:?}", rest, e)).ok(); }
                }
            } else if !cmd.is_empty() {
                // ブロードキャストメッセージ
                let mut remove = Vec::new();
                for (i, c) in clients.iter_mut().enumerate() {
                    if let Err(e) = c.write_all(cmd.as_bytes()) { tx_main.send(format!("Write error to {}: {:?}", i, e)).ok(); remove.push(i); }
                }
                for i in remove.into_iter().rev() { clients.remove(i); }
            }
        }

        // accept
        if let Some(l) = &listener {
            loop {
                match l.accept() {
                    Ok((s, peer)) => { let s=s; s.set_nonblocking(true).ok(); clients.push(s); tx_main.send(format!("Accepted {} (id={})", peer, clients.len()-1)).ok(); }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => { tx_main.send(format!("Accept error: {:?}", e)).ok(); break; }
                }
            }
        }

        // 読み取り
        let mut received: Vec<(usize,String)> = Vec::new();
        let mut remove_indices: Vec<usize> = Vec::new();
        for (idx, c) in clients.iter_mut().enumerate() {
            match c.read(&mut buf) {
                Ok(0) => { tx_main.send(format!("Client {} closed", idx)).ok(); remove_indices.push(idx); }
                Ok(n) => { if n>0 { received.push((idx, String::from_utf8_lossy(&buf[..n]).to_string())); } }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => { tx_main.send(format!("Read error {}: {:?}", idx, e)).ok(); remove_indices.push(idx); }
            }
        }

        // 中継
        for (src, msg) in received.iter() {
            tx_main.send(format!("受信(id={}): {}", src, msg)).ok();
            for (idx, c) in clients.iter_mut().enumerate() {
                if idx == *src { continue; }
                if let Err(e) = c.write_all(msg.as_bytes()) { tx_main.send(format!("Relay write error to {}: {:?}", idx, e)).ok(); remove_indices.push(idx); }
            }
        }

        // 削除
        remove_indices.sort_unstable(); remove_indices.dedup();
        for i in remove_indices.into_iter().rev() { clients.remove(i); }

        thread::sleep(Duration::from_millis(15));
    }
}
