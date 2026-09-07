//! 各シナリオ（サブコマンド）の実装。
//! すべて実際の network_handler を実TCPループバック経由で動かす。

use crate::harness::*;
use p2witter::core::crypto;
use p2witter::core::protocol::{self, Message};
use p2witter::utils::current_unix_millis;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::net::TcpStream;

fn signed_hello(handle: &str, pkcs8: &[u8], public: &[u8]) -> Vec<u8> {
    let mut m = Message::hello(current_unix_millis(), handle);
    // 署名対象バイトは公開鍵を含むため、署名前に public_key を設定する
    m.public_key = Some(public.to_vec());
    let data = protocol::signing_bytes(&m);
    let sig = crypto::sign_ed25519(&data, pkcs8).expect("sign");
    m.signature = Some(sig);
    protocol::encode(&m)
}

fn signed_chat(text: &str, pkcs8: &[u8], public: &[u8]) -> Vec<u8> {
    let mut m = Message::chat(text, current_unix_millis());
    m.public_key = Some(public.to_vec());
    let data = protocol::signing_bytes(&m);
    let sig = crypto::sign_ed25519(&data, pkcs8).expect("sign");
    m.signature = Some(sig);
    protocol::encode(&m)
}

/// 接続＋チャット中継: A が待受、B が接続、A が投稿 → B に届く。
pub async fn two_clients() {
    let port_a = free_port();
    let mut a = Node::spawn(port_a, "@alice");
    let mut b = Node::spawn(free_port(), "@bob");
    a.handle("@alice").await;
    b.handle("@bob").await;
    a.open().await;
    // リスナが実際にバインドされるまで待ってから接続（接続拒否回避）
    let listening = a
        .wait_for(|m| m.contains("待受開始"), Duration::from_secs(5))
        .await;
    assert_event(listening, "[two-clients] A listening");
    b.connect(&connect_token(port_a)).await;

    // リスナ(A)が受入を完了してから投稿する（受信側登録前に放送されないよう）
    let accepted = a
        .wait_for(|m| m.contains("接続受入"), Duration::from_secs(5))
        .await;
    assert_event(accepted, "[two-clients] A accepted B");
    let connected = b
        .wait_for(|m| m.contains("接続完了"), Duration::from_secs(5))
        .await;
    assert_event(connected, "[two-clients] B connected to A");

    a.chat("hello").await;
    let got = b
        .wait_for(
            |m| m.contains("hello") && m.ends_with('○'),
            Duration::from_secs(5),
        )
        .await;
    match got {
        Some(m) => println!("[two-clients] OK: B received -> {}", m),
        None => fail("[two-clients] B did not receive chat from A"),
    }
}

/// 3ノード以上の中継: A-B-C チェーン。A の投稿が B を経由して C に届く。
pub async fn three_relay() {
    let port_a = free_port();
    let mut a = Node::spawn(port_a, "@alice");
    let mut b = Node::spawn(free_port(), "@bob");
    let port_c = free_port();
    let mut c = Node::spawn(port_c, "@carol");
    a.handle("@alice").await;
    b.handle("@bob").await;
    c.handle("@carol").await;
    // フェーズ1: リスナをバインドしてから接続（接続拒否回避）
    a.open().await;
    let _ = a
        .wait_for(|m| m.contains("待受開始"), Duration::from_secs(5))
        .await;
    c.open().await;
    let _ = c
        .wait_for(|m| m.contains("待受開始"), Duration::from_secs(5))
        .await;
    // フェーズ2: B が A と C に接続
    b.connect(&connect_token(port_a)).await;
    b.connect(&connect_token(port_c)).await;

    // 受入確認
    let _ = a
        .wait_for(|m| m.contains("接続受入"), Duration::from_secs(5))
        .await;
    let _ = c
        .wait_for(|m| m.contains("接続受入"), Duration::from_secs(5))
        .await;
    let _ = b
        .wait_for(|m| m.contains("接続完了"), Duration::from_secs(5))
        .await;
    let _ = b
        .wait_for(|m| m.contains("接続完了"), Duration::from_secs(5))
        .await;

    a.chat("relay-test").await;
    let got = c
        .wait_for(
            |m| m.contains("relay-test") && m.ends_with('○'),
            Duration::from_secs(5),
        )
        .await;
    match got {
        Some(m) => println!("[three-relay] OK: C received via B -> {}", m),
        None => fail("[three-relay] C did not receive relayed chat"),
    }
}

/// 不正検知・切断: 不正署名付き HELLO を送ると相手が切断する。
pub async fn invalid_hello() {
    let port = free_port();
    let mut n = Node::spawn(port, "@victim");
    n.handle("@victim").await;
    n.open().await;
    settle(Duration::from_millis(300)).await;

    let mut stream = raw_connect(&format!("127.0.0.1:{}", port))
        .await
        .expect("raw connect");
    let kp = crypto::generate_ed25519_keypair().unwrap();
    let mut m = Message::hello(current_unix_millis(), "@mallory");
    m.public_key = Some(kp.public.clone());
    m.signature = Some(vec![0u8; 64]); // 不正署名
    send_raw(&mut stream, &protocol::encode(&m)).await;

    let got = n
        .wait_for(
            |e| e.contains("不正HELLO") || (e.contains("切断") && e.contains("3")),
            Duration::from_secs(5),
        )
        .await;
    match got {
        Some(m) => println!("[invalid-hello] OK: victim disconnected intruder -> {}", m),
        None => fail("[invalid-hello] victim did not reject bad-signature HELLO"),
    }
}

/// 不正検知・切断: ハンドル長超過(>=80文字)の HELLO を送ると切断する(reason 2)。
pub async fn invalid_handle() {
    let port = free_port();
    let mut n = Node::spawn(port, "@victim");
    n.handle("@victim").await;
    n.open().await;
    settle(Duration::from_millis(300)).await;

    let mut stream = raw_connect(&format!("127.0.0.1:{}", port))
        .await
        .expect("raw connect");
    let kp = crypto::generate_ed25519_keypair().unwrap();
    let long_handle = format!("@{}", "a".repeat(90));
    let frame = signed_hello(&long_handle, &kp.pkcs8, &kp.public);
    send_raw(&mut stream, &frame).await;

    let got = n
        .wait_for(
            |e| e.contains("不正HELLO") || (e.contains("切断") && e.contains("2")),
            Duration::from_secs(5),
        )
        .await;
    match got {
        Some(m) => println!("[invalid-handle] OK: victim disconnected oversized handle -> {}", m),
        None => fail("[invalid-handle] victim did not reject oversized handle"),
    }
}

/// 不正検知・切断: 本文に超長ハンドルを含む CHAT を送ると切断する(reason 1)。
pub async fn invalid_chat_handle() {
    let port = free_port();
    let mut n = Node::spawn(port, "@victim");
    n.handle("@victim").await;
    n.open().await;
    settle(Duration::from_millis(300)).await;

    let mut stream = raw_connect(&format!("127.0.0.1:{}", port))
        .await
        .expect("raw connect");
    let kp = crypto::generate_ed25519_keypair().unwrap();
    let long = format!("@{}: hi", "b".repeat(90));
    let frame = signed_chat(&long, &kp.pkcs8, &kp.public);
    send_raw(&mut stream, &frame).await;

    let got = n
        .wait_for(
            |e| e.contains("ハンドル長") || (e.contains("切断") && e.contains("1")),
            Duration::from_secs(5),
        )
        .await;
    match got {
        Some(m) => {
            println!("[invalid-chat-handle] OK: victim disconnected bad chat -> {}", m)
        }
        None => fail("[invalid-chat-handle] victim did not reject oversized chat handle"),
    }
}

/// ランダム生成された N ノード規模のネットワークで自動的に色々やる。
pub async fn scale20(nodes: usize, seed: u64, duration: Duration, fanout: usize) {
    let mut rng = Rng::new(seed);
    let ports: Vec<u16> = (0..nodes).map(|_| free_port()).collect();
    let mut net: Vec<Node> = Vec::new();
    for i in 0..nodes {
        let node = Node::spawn(ports[i], &format!("@node{}", i));
        node.handle(&format!("@node{}", i)).await;
        node.open().await;
        net.push(node);
    }
    // フェーズ1: 全リスナがバインドされるまで待つ（接続拒否回避）
    for node in net.iter_mut() {
        let _ = node
            .wait_for(|m| m.contains("待受開始"), Duration::from_secs(5))
            .await;
    }

    // ランダムトポロジ: 各ノードが fanout 個の別ノードへ接続
    for i in 0..nodes {
        let mut cand: Vec<usize> = (0..nodes).filter(|&j| j != i).collect();
        rng.shuffle(&mut cand);
        for t in cand.into_iter().take(fanout) {
            net[i].connect(&connect_token(ports[t])).await;
        }
    }
    settle(Duration::from_secs(2)).await;

    // 全ノードのイベントログを蓄積（最終解析用）
    let mut logs: Vec<Vec<String>> = (0..nodes).map(|_| Vec::new()).collect();

    // アクティビティループ: ランダムな送信元からユニークタグを投稿
    let mut sent: Vec<(u64, usize)> = Vec::new();
    let mut seq: u64 = 0;
    let start = tokio::time::Instant::now();
    while start.elapsed() < duration {
        let src = rng.below(nodes);
        seq += 1;
        let tag = format!("MSG-{}", seq);
        net[src].chat(&tag).await;
        sent.push((seq, src));
        tokio::time::sleep(Duration::from_millis(150)).await;
        for (idx, node) in net.iter_mut().enumerate() {
            for ev in node.drain_available() {
                logs[idx].push(ev);
            }
        }
    }

    // 不正ノード注入: ランダムなノードへ不正署名 HELLO を送る
    let victim = rng.below(nodes);
    let mut stream: TcpStream = raw_connect(&format!("127.0.0.1:{}", ports[victim]))
        .await
        .expect("raw connect to victim");
    let kp = crypto::generate_ed25519_keypair().unwrap();
    let mut m = Message::hello(current_unix_millis(), "@intruder");
    m.public_key = Some(kp.public.clone());
    m.signature = Some(vec![0u8; 64]);
    send_raw(&mut stream, &protocol::encode(&m)).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 最終ドレイン
    for (idx, node) in net.iter_mut().enumerate() {
        for ev in node.drain_available() {
            logs[idx].push(ev);
        }
    }

    // カバレッジ集計
    let mut received: HashMap<u64, HashSet<usize>> = HashMap::new();
    for (idx, log) in logs.iter().enumerate() {
        for ev in log {
            if let Some(n) = extract_msg_seq(ev) {
                received.entry(n).or_default().insert(idx);
            }
        }
    }
    let total = sent.len();
    let mut covered = 0usize;
    let mut sum_cov = 0usize;
    for (s, _) in &sent {
        if let Some(set) = received.get(s) {
            covered += 1;
            sum_cov += set.len();
        }
    }
    let cov_ratio = if total > 0 {
        covered as f64 / total as f64
    } else {
        0.0
    };
    let avg = if total > 0 {
        sum_cov as f64 / total as f64
    } else {
        0.0
    };
    println!(
        "[scale20] nodes={} msgs={} covered={} ({:.1}%) avg_receivers_per_msg={:.2}",
        nodes, total, covered, cov_ratio * 100.0, avg
    );

    // 不正ノード検知の確認
    let detected = logs[victim]
        .iter()
        .any(|e| e.contains("不正HELLO") || (e.contains("切断") && e.contains("3")));
    if detected {
        println!("[scale20] OK: invalid node detected by @node{}", victim);
    } else {
        fail(&format!(
            "[scale20] invalid node NOT detected by @node{}",
            victim
        ));
    }

    if covered < total {
        println!(
            "[scale20] WARN: {} 件が誰にも届かなかった（トポロジ分離等の可能性）",
            total - covered
        );
    }
    println!("[scale20] DONE");
}

fn extract_msg_seq(ev: &str) -> Option<u64> {
    let pos = ev.find("MSG-")?;
    let rest = &ev[pos + 4..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u64>().ok()
}

fn assert_event(opt: Option<String>, label: &str) {
    match opt {
        Some(m) => println!("{} (event: {})", label, m),
        None => fail(label),
    }
}

fn fail(msg: &str) -> ! {
    println!("FAIL: {}", msg);
    std::process::exit(1);
}
