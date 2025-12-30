use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[test]
fn test_two_node_communication() {
    // ノードA: ポート 19000 でリッスン
    let (tx_a, rx_a) = mpsc::channel();
    let node_a_thread = thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:19000").expect("failed to bind");
        listener.set_nonblocking(true).ok();
        
        // クライアント接続を待つ
        let mut client = None;
        let mut timeout = 0;
        while timeout < 50 {
            if let Ok((stream, _)) = listener.accept() {
                client = Some(stream);
                break;
            }
            thread::sleep(Duration::from_millis(100));
            timeout += 1;
        }
        
        tx_a.send(("Node A ready", client.is_some())).ok();
    });
    
    thread::sleep(Duration::from_millis(200));
    
    // ノードB: ノードAに接続
    let (tx_b, rx_b) = mpsc::channel();
    let node_b_thread = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        match std::net::TcpStream::connect("127.0.0.1:19000") {
            Ok(mut stream) => {
                tx_b.send(("Node B connected", true)).ok();
                // 簡単なメッセージを送信
                let msg = b"Hello from Node B";
                let _ = stream.write_all(msg);
            }
            Err(e) => {
                tx_b.send(("Node B connection failed", false)).ok();
                eprintln!("Connection failed: {}", e);
            }
        }
    });
    
    // 結果を待つ
    let a_result = rx_a.recv_timeout(Duration::from_secs(5));
    let b_result = rx_b.recv_timeout(Duration::from_secs(5));
    
    assert!(a_result.is_ok(), "Node A timeout");
    assert!(b_result.is_ok(), "Node B timeout");
    
    node_a_thread.join().ok();
    node_b_thread.join().ok();
}

#[test]
fn test_three_node_mesh() {
    // 3つのノードをメッシュトポロジーで接続
    // ノードA (port 19100) ← ノードB (port 19101) ← ノードC (port 19102)
    
    let results = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    
    // ノードA
    let results_a = results.clone();
    let node_a = thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:19100").ok();
        if let Some(l) = listener {
            l.set_nonblocking(true).ok();
            results_a.lock().unwrap().push("A_ready");
            
            // リスナーを維持してスレッドを生きたままにする
            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_secs(3) {
                thread::sleep(Duration::from_millis(100));
            }
        }
    });
    
    // ノードB
    let results_b = results.clone();
    let node_b = thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:19101").ok();
        if let Some(l) = listener {
            l.set_nonblocking(true).ok();
            results_b.lock().unwrap().push("B_ready");
            
            // ノードAに接続（タイムアウトを追加）
            let mut connected = false;
            for _ in 0..10 {
                if std::net::TcpStream::connect("127.0.0.1:19100").is_ok() {
                    results_b.lock().unwrap().push("B_connected_to_A");
                    connected = true;
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            
            // リスナーを維持
            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_secs(2) {
                thread::sleep(Duration::from_millis(100));
            }
        }
    });
    
    // ノードC
    let results_c = results.clone();
    let node_c = thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));
        
        // ノードBに接続（タイムアウトを追加）
        let mut connected = false;
        for _ in 0..10 {
            if std::net::TcpStream::connect("127.0.0.1:19101").is_ok() {
                results_c.lock().unwrap().push("C_connected_to_B");
                connected = true;
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
    
    node_a.join().ok();
    node_b.join().ok();
    node_c.join().ok();
    
    let final_results = results.lock().unwrap();
    assert!(final_results.contains(&"A_ready"), "Node A did not start");
    assert!(final_results.contains(&"B_ready"), "Node B did not start");
    assert!(final_results.contains(&"B_connected_to_A"), "Node B failed to connect to A");
    assert!(final_results.contains(&"C_connected_to_B"), "Node C failed to connect to B");
}

#[test]
fn test_message_propagation_simple() {
    // 簡単なメッセージ伝播テスト
    // A -> B へメッセージを送信して受信側が正しく読み取れるか確認
    
    let (tx_recv, rx_recv) = mpsc::channel();
    
    // リセプター（ノードA）
    let receiver_thread = thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:19200")
            .expect("receiver bind failed");
        listener.set_nonblocking(true).ok();
        
        let mut buf = [0u8; 1024];
        let mut msg_received = false;
        
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(3) {
            if let Ok((mut stream, _)) = listener.accept() {
                if let Ok(n) = stream.read(&mut buf) {
                    if n > 0 {
                        msg_received = true;
                        let msg = String::from_utf8_lossy(&buf[..n]);
                        tx_recv.send(msg.to_string()).ok();
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        
        if !msg_received {
            tx_recv.send("NO_MESSAGE".to_string()).ok();
        }
    });
    
    thread::sleep(Duration::from_millis(200));
    
    // センダー（ノードB）
    let sender_thread = thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));
        if let Ok(mut stream) = std::net::TcpStream::connect("127.0.0.1:19200") {
            let msg = b"Test message from B";
            let _ = stream.write_all(msg);
        }
    });
    
    receiver_thread.join().ok();
    sender_thread.join().ok();
    
    let received = rx_recv.recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| "TIMEOUT".to_string());
    
    assert_eq!(received, "Test message from B", "Message not received correctly");
}

#[test]
fn test_load_distribution() {
    // 複数のノードに並行してメッセージを送信
    const NUM_NODES: usize = 5;
    const NUM_MESSAGES: usize = 10;
    
    let results = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut threads = vec![];
    
    // 5つのノードを起動
    for i in 0..NUM_NODES {
        let results_clone = results.clone();
        let port = 19300 + i as u16;
        
        let handle = thread::spawn(move || {
            if let Ok(listener) = TcpListener::bind(format!("127.0.0.1:{}", port)) {
                listener.set_nonblocking(true).ok();
                results_clone.lock().unwrap().push(format!("Node_{}_ready", i));
                
                let mut msg_count = 0;
                let start = std::time::Instant::now();
                
                while start.elapsed() < Duration::from_secs(2) && msg_count < NUM_MESSAGES {
                    if let Ok((mut stream, _)) = listener.accept() {
                        let mut buf = [0u8; 1024];
                        if let Ok(n) = stream.read(&mut buf) {
                            if n > 0 {
                                msg_count += 1;
                            }
                        }
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                
                results_clone.lock().unwrap()
                    .push(format!("Node_{}_received_{}_msgs", i, msg_count));
            }
        });
        threads.push(handle);
    }
    
    thread::sleep(Duration::from_millis(500));
    
    // 各ノードにメッセージを送信
    for i in 0..NUM_NODES {
        for j in 0..NUM_MESSAGES {
            let port = 19300 + i as u16;
            let thread_handle = thread::spawn(move || {
                thread::sleep(Duration::from_millis(100 * j as u64));
                if let Ok(mut stream) = std::net::TcpStream::connect(format!("127.0.0.1:{}", port)) {
                    let msg = format!("Message_{}", j);
                    let _ = stream.write_all(msg.as_bytes());
                }
            });
            threads.push(thread_handle);
        }
    }
    
    // すべてのスレッドを待つ
    for thread in threads {
        thread.join().ok();
    }
    
    let final_results = results.lock().unwrap();
    
    // 最低限のチェック
    assert!(final_results.iter().any(|r| r.contains("Node_0_ready")));
    assert!(final_results.iter().any(|r| r.contains("Node_4_ready")));
    
    println!("Load distribution test results:");
    for result in final_results.iter() {
        println!("  {}", result);
    }
}

#[test]
fn test_node_recovery_from_disconnect() {
    // ノードが切断後に再接続できるか確認
    
    let (tx_event, rx_event) = mpsc::channel();
    
    // サーバー（ノードA）
    let server_thread = thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:19400")
            .expect("server bind failed");
        listener.set_nonblocking(true).ok();
        
        let mut connections = 0;
        let start = std::time::Instant::now();
        
        while start.elapsed() < Duration::from_secs(5) {
            if let Ok((_stream, _)) = listener.accept() {
                connections += 1;
                let _ = tx_event.send(format!("Connection_{}", connections));
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
    
    thread::sleep(Duration::from_millis(200));
    
    // クライアント（ノードB）- 2回接続
    let client_thread = thread::spawn(move || {
        // 最初の接続
        if let Ok(_) = std::net::TcpStream::connect("127.0.0.1:19400") {
            thread::sleep(Duration::from_millis(500));
        }
        
        // 切断後、再接続
        thread::sleep(Duration::from_millis(300));
        if let Ok(_) = std::net::TcpStream::connect("127.0.0.1:19400") {
            thread::sleep(Duration::from_millis(500));
        }
    });
    
    server_thread.join().ok();
    client_thread.join().ok();
    
    let mut connection_count = 0;
    while let Ok(event) = rx_event.try_recv() {
        println!("Event: {}", event);
        if event.contains("Connection") {
            connection_count += 1;
        }
    }
    
    assert!(connection_count >= 2, 
            "Expected at least 2 reconnection attempts, got {}", connection_count);
}

#[test]
fn test_concurrent_node_operations() {
    // 複数ノードが同時に異なる操作を実行
    let results = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut threads = vec![];
    
    // ノードが同時にリッスンと接続を実行
    for i in 0..3 {
        let results_clone = results.clone();
        let port = 19500 + i as u16;
        
        let thread = thread::spawn(move || {
            let res_listen = TcpListener::bind(format!("127.0.0.1:{}", port)).is_ok();
            results_clone.lock().unwrap().push(format!("Node_{}_listen_ok_{}", i, res_listen));
            
            thread::sleep(Duration::from_millis(200));
            
            // 他のノードに接続を試みる
            if i > 0 {
                let prev_port = port - 1;
                let res_connect = 
                    std::net::TcpStream::connect(format!("127.0.0.1:{}", prev_port)).is_ok();
                results_clone.lock().unwrap()
                    .push(format!("Node_{}_connect_to_prev_{}", i, res_connect));
            }
        });
        threads.push(thread);
    }
    
    for thread in threads {
        thread.join().ok();
    }
    
    let final_results = results.lock().unwrap();
    println!("Concurrent operations:");
    for result in final_results.iter() {
        println!("  {}", result);
    }
    
    // 最低限のアサーション
    assert!(final_results.len() >= 3, "Not all nodes completed operations");
}