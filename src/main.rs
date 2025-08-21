use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

fn main() {
    // メインスレッドと通信するためのチャンネル
    let (tx_to_main, rx_from_threads) = mpsc::channel::<String>();
    
    let mut active_thread_tx: Option<Sender<String>> = None;
    let mut active_thread_handle: Option<thread::JoinHandle<()>> = None;
    
    loop {
        // 他スレッドからのメッセージを継続的にチェック・表示
        let mut has_new_messages = false;
        while let Ok(msg) = rx_from_threads.try_recv() {
            if !has_new_messages {
                // 最初のメッセージの前に改行
                println!();
                has_new_messages = true;
            }
            print!("{}", msg);
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
                println!("\r{}", " ".repeat(50)); // プロンプト行をクリア
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
                if let Some(addr) = parts.get(1) {
                    let addr = addr.clone();
                    let tx_main = tx_to_main.clone();
                    let (tx_thread, rx_thread) = mpsc::channel();
                    active_thread_tx = Some(tx_thread);
                    let handle = thread::spawn(move || {
                        run_tcp_server(&addr, tx_main, rx_thread);
                    });
                    active_thread_handle = Some(handle);
                } else {
                    println!("Usage: /server <port>");
                }
            }
            Some("/client") => {
                if let Some(addr) = parts.get(1) {
                    let addr = addr.clone();
                    let tx_main = tx_to_main.clone();
                    let (tx_thread, rx_thread) = mpsc::channel();
                    active_thread_tx = Some(tx_thread);
                    let handle = thread::spawn(move || {
                        run_tcp_client(&addr, tx_main, rx_thread);
                    });
                    active_thread_handle = Some(handle);
                } else {
                    println!("Usage: /client <addr:port>");
                }
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
                if let Some(ref tx) = active_thread_tx {
                    if tx.send(cmd.to_string()).is_ok() {
                        // メッセージをアクティブなスレッドに送信
                    } else {
                        println!("No active connection");
                        active_thread_tx = None;
                    }
                } else {
                    println!("Unknown command: {}", cmd);
                }
            }
            None => {
                // 空行の場合、アクティブなスレッドに送信
                if let Some(ref tx) = active_thread_tx {
                    if tx.send(String::new()).is_err() {
                        active_thread_tx = None;
                    }
                }
            }
        }
    }
}

fn run_tcp_server(port: &str, tx_main: Sender<String>, rx_thread: Receiver<String>) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).expect("Could not bind");
    tx_main.send(format!("Server listening on 127.0.0.1:{}", port)).ok();

    // ノンブロッキングモードに設定
    listener.set_nonblocking(true).ok();

    loop {
        // 終了コマンドをチェック
        match rx_thread.try_recv() {
            Ok(cmd) if cmd == "/exit" => {
                tx_main.send("Server shutting down...".to_string()).ok();
                break;
            }
            Ok(_) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                tx_main.send("Main thread disconnected, server shutting down...".to_string()).ok();
                break;
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }

        // 接続を受け付け
        match listener.accept() {
            Ok((mut stream, peer_addr)) => {
                tx_main.send(format!("Client connected: {}", peer_addr)).ok();
                stream.set_nonblocking(true).ok(); // クライアントソケットもノンブロッキングに

                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => {
                            // connection closed
                            break;
                        }
                        Ok(n) => {
                            let msg = String::from_utf8_lossy(&buf[..n]);
                            tx_main.send(format!("受信メッセージ: {}", msg)).ok();
                            if let Err(e) = stream.write_all(msg.as_bytes()) {
                                tx_main.send(format!("Write error: {:?}", e)).ok();
                                break;
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // データがない場合は少し待機して再度ループ
                            thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                        Err(e) => {
                            tx_main.send(format!("Read error: {:?}", e)).ok();
                            break;
                        }
                    }
                }
                tx_main.send(format!("Client {} disconnected", peer_addr)).ok();
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // 接続なし（ノンブロッキング）
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                tx_main.send(format!("Connection failed: {:?}", e)).ok();
            }
        }
    }
    
    tx_main.send("Server thread finished".to_string()).ok();
}

fn run_tcp_client(addr: &str, tx_main: Sender<String>, rx_thread: Receiver<String>) {
    tx_main.send(format!("TCP client connect to {}", addr)).ok();
    let mut stream = match TcpStream::connect(addr) {
        Ok(stream) => {
            // ノンブロッキングモードに設定
            stream.set_nonblocking(true).ok();
            stream
        },
        Err(e) => {
            tx_main.send(format!("Could not connect to {}: {:?}", addr, e)).ok();
            return;
        }
    };

    loop {
        // 応答を非同期で受信チェック
        let mut buf = [0u8; 1024];
        match stream.read(&mut buf) {
            Ok(read) if read > 0 => {
                let reply = String::from_utf8_lossy(&buf[..read]);
                tx_main.send(format!("受信: {}", reply)).ok();
            }
            Ok(_) => {
                tx_main.send("Server disconnected".to_string()).ok();
                break;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // データがない（ノンブロッキング）
            }
            Err(e) => {
                tx_main.send(format!("Failed to read from server: {:?}", e)).ok();
                break;
            }
        }
        
        // メインスレッドからのメッセージを受信
        match rx_thread.try_recv() {
            Ok(input) => {
                if input == "/exit" {
                    tx_main.send("Exiting client...".to_string()).ok();
                    break;
                }
                if !input.is_empty() {
                    // メッセージを送信
                    if let Err(e) = stream.write_all(input.as_bytes()) {
                        tx_main.send(format!("Failed to send message: {:?}", e)).ok();
                        break;
                    }
                    stream.flush().ok();
                    tx_main.send(format!("送信: {}", input)).ok();
                }
            }
            Err(mpsc::TryRecvError::Empty) => {
                // メッセージなし、少し待機
                thread::sleep(Duration::from_millis(10));
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                tx_main.send("Main thread disconnected, client shutting down...".to_string()).ok();
                break;
            }
        }
    }
    
    tx_main.send("Client thread finished".to_string()).ok();
}
