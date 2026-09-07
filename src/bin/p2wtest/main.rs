//! 複数クライアントを実際に動かすネットワーク実験/テスト用バイナリ。
//!
//! 使い方: cargo run --bin p2wtest -- <scenario> [options]
//!   two-clients          2ノード接続＋チャット中継
//!   three-relay          3ノード(A-B-C)の中継
//!   invalid-hello        不正署名HELLO → 切断
//!   invalid-handle       ハンドル長超過HELLO → 切断
//!   invalid-chat-handle  超長ハンドルを含むCHAT → 切断
//!   scale20 [--nodes N] [--seed S] [--duration SEC] [--fanout K]
//!                         ランダムNノード網で自動実験

mod harness;
mod scenarios;

use std::time::Duration;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let scenario = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let result = tokio::time::timeout(Duration::from_secs(15), dispatch(scenario, &args)).await;
    if result.is_err() {
        eprintln!("FAIL: scenario '{}' timed out (60s)", scenario);
        std::process::exit(1);
    }
    // ハンドラタスクは無限ループのため、通常リターンでは runtime シャットダウンが
    // 待機してハングする。成功時も明示的に終了する。
    std::process::exit(0);
}

async fn dispatch(scenario: &str, args: &[String]) {
    match scenario {
        "two-clients" => scenarios::two_clients().await,
        "three-relay" => scenarios::three_relay().await,
        "invalid-hello" => scenarios::invalid_hello().await,
        "invalid-handle" => scenarios::invalid_handle().await,
        "invalid-chat-handle" => scenarios::invalid_chat_handle().await,
        "scale20" => {
            let mut nodes = 20usize;
            let mut seed = 1u64;
            let mut dur = Duration::from_secs(10);
            let mut fanout = 3usize;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--nodes" => {
                        nodes = args[i + 1].parse().expect("invalid --nodes");
                        i += 2;
                    }
                    "--seed" => {
                        seed = args[i + 1].parse().expect("invalid --seed");
                        i += 2;
                    }
                    "--duration" => {
                        dur = Duration::from_secs(args[i + 1].parse().expect("invalid --duration"));
                        i += 2;
                    }
                    "--fanout" => {
                        fanout = args[i + 1].parse().expect("invalid --fanout");
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            scenarios::scale20(nodes, seed, dur, fanout).await;
        }
        _ => {
            println!("usage: p2wtest <scenario> [options]");
            println!("scenarios:");
            println!("  two-clients");
            println!("  three-relay");
            println!("  invalid-hello");
            println!("  invalid-handle");
            println!("  invalid-chat-handle");
            println!("  scale20 [--nodes N] [--seed S] [--duration SEC] [--fanout K]");
        }
    }
}
