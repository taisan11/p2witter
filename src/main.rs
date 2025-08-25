use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self};
use std::time::Duration;

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
                if let Some(addr) = parts.get(1) {
                    let addr = addr.clone();
                    let tx_main = tx_to_main.clone();
                    let (tx_thread, rx_thread) = mpsc::channel();
                    active_thread_tx = Some(tx_thread);
                    let handle = thread::spawn(move || {
                        start_server(&addr, tx_main, rx_thread);
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
                        start_client(&addr, tx_main, rx_thread);
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

fn start_server(port: &str, tx_main: Sender<String>, rx_thread: Receiver<String>) {
    tx_main.send(format!("server mode start: {}", port)).ok();
    let listener = match TcpListener::bind(format!("127.0.0.1:{}", port)) {
        Ok(l) => l,
        Err(e) => { tx_main.send(format!("Bind error: {:?}", e)).ok(); return; }
    };
    listener.set_nonblocking(true).ok();
    tx_main.send(format!("Listening 127.0.0.1:{} (one client)", port)).ok();
    // /exit を待ちつつ accept
    let stream = loop {
        if let Ok(cmd) = rx_thread.try_recv() {
            if cmd == "/exit" { tx_main.send("/exit before accept".to_string()).ok(); return; }
        }
        match listener.accept() {
            Ok((s, peer)) => { s.set_nonblocking(true).ok(); tx_main.send(format!("Accepted: {}", peer)).ok(); break s; }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => { thread::sleep(Duration::from_millis(50)); }
            Err(e) => { tx_main.send(format!("Accept error: {:?}", e)).ok(); return; }
        }
    };
    run_tcp(stream, tx_main, rx_thread);
    // run_tcp 終了後
}

fn start_client(addr: &str, tx_main: Sender<String>, rx_thread: Receiver<String>) {
    tx_main.send(format!("client connect to: {}", addr)).ok();
    let stream = match TcpStream::connect(addr) {
        Ok(s) => { s.set_nonblocking(true).ok(); tx_main.send("Connected".to_string()).ok(); s }
        Err(e) => { tx_main.send(format!("Connect error: {:?}", e)).ok(); return; }
    };
    run_tcp(stream, tx_main, rx_thread);
}

fn run_tcp(mut stream: TcpStream, tx_main: Sender<String>, rx_thread: Receiver<String>) {
    const ECHO_PREFIX: &str = "[echo] ";
    tx_main.send("session started".to_string()).ok();
    let mut buf = [0u8; 1024];
    loop {
        // 送信指示
        match rx_thread.try_recv() {
            Ok(cmd) => {
                if cmd == "/exit" { tx_main.send("Exit -> closing".to_string()).ok(); break; }
                if !cmd.is_empty() {
                    if let Err(e) = stream.write_all(cmd.as_bytes()) { tx_main.send(format!("Write error: {:?}", e)).ok(); break; }
                    // tx_main.send(format!("送信: {}", cmd)).ok();
                }
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => { tx_main.send("Main disconnected".to_string()).ok(); break; }
        }
        // 受信
        match stream.read(&mut buf) {
            Ok(0) => { tx_main.send("Peer closed".to_string()).ok(); break; }
            Ok(n) => {
                let msg = String::from_utf8_lossy(&buf[..n]).to_string();
                tx_main.send(format!("受信: {}", msg)).ok();
                if !msg.starts_with(ECHO_PREFIX) { // エコー返し
                    let echo = format!("{}{}", ECHO_PREFIX, msg);
                    if let Err(e) = stream.write_all(echo.as_bytes()) { tx_main.send(format!("Echo write error: {:?}", e)).ok(); break; }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => { tx_main.send(format!("Read error: {:?}", e)).ok(); break; }
        }
        thread::sleep(Duration::from_millis(10));
    }
    tx_main.send("session finished".to_string()).ok();
}
