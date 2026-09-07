//! 複数クライアントを1プロセス内で起動し、実際の network_handler を
//! 実TCPループバック経由で動かすためのテストハーネス。
//!
//! 各 `Node` は固有の設定(鍵/ハンドル)と sled データベースを持ち、
//! グローバルな singleton を共有しない。

use p2witter::config::Config;
use p2witter::core::{crypto, rpc};
use p2witter::network_handler;
use p2witter::storage::Storage;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use tokio::time::sleep;

static NODE_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub struct Node {
    pub port: u16,
    tx_cmd: mpsc::Sender<rpc::Command>,
    rx_event: mpsc::Receiver<rpc::Event>,
    _tmpdir: std::path::PathBuf,
}

impl Node {
    /// 固有の一時ディレクトリ・鍵・ストレージでノードを起動する。
    pub fn spawn(port: u16, handle: &str) -> Node {
        let id = NODE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let tmpdir = std::env::temp_dir().join(format!(
            "p2witter-test-{}-{}",
            std::process::id(),
            id
        ));
        std::fs::create_dir_all(&tmpdir).expect("temp dir create failed");
        // 鍵生成
        let ed = crypto::generate_ed25519_keypair().expect("ed25519 gen");
        let (x25519_priv, x25519_pub) = crypto::generate_x25519_keypair().expect("x25519 gen");

        // 設定テーブル構築
        let mut root = toml::Table::new();
        root.insert("debug".to_string(), toml::Value::Boolean(false));
        let mut user = toml::Table::new();
        user.insert("handle".to_string(), toml::Value::String(handle.to_string()));
        root.insert("user".to_string(), toml::Value::Table(user));
        let mut key = toml::Table::new();
        key.insert("pkcs8".to_string(), toml::Value::String(crypto::to_hex(&ed.pkcs8)));
        key.insert("public".to_string(), toml::Value::String(crypto::to_hex(&ed.public)));
        key.insert(
            "x25519".to_string(),
            toml::Value::String(crypto::to_hex(&x25519_priv)),
        );
        key.insert(
            "x25519_pub".to_string(),
            toml::Value::String(crypto::to_hex(&x25519_pub)),
        );
        root.insert("key".to_string(), toml::Value::Table(key));
        let cfg = Config::from_table(root);

        let db_path = tmpdir.join("p2witter.db");
        let db = Storage::open(db_path.to_str().unwrap()).expect("storage open");

        let (tx_main, rx_event) = mpsc::channel::<rpc::Event>(1024);
        let (tx_cmd, rx_thread) = mpsc::channel::<rpc::Command>(256);

        tokio::spawn(async move {
            network_handler::network_handler(tx_main, rx_thread, cfg, db).await;
        });

        Node {
            port,
            tx_cmd,
            rx_event,
            _tmpdir: tmpdir,
        }
    }

    pub async fn open(&self) {
        self.tx_cmd
            .send(rpc::Command::Open {
                port: self.port.to_string(),
                public_host: None,
            })
            .await
            .ok();
    }

    pub async fn handle(&self, name: &str) {
        self.tx_cmd
            .send(rpc::Command::Handle(name.to_string()))
            .await
            .ok();
    }

    pub async fn connect(&self, token: &str) {
        self.tx_cmd
            .send(rpc::Command::Connect(token.to_string()))
            .await
            .ok();
    }

    pub async fn chat(&self, text: &str) {
        self.tx_cmd
            .send(rpc::Command::Chat(text.to_string()))
            .await
            .ok();
    }

    /// 条件を満たすイベントが届くまで待つ。タイムアウトなら None。
    pub async fn wait_for<F>(&mut self, pred: F, dur: Duration) -> Option<String>
    where
        F: Fn(&str) -> bool,
    {
        let deadline = tokio::time::Instant::now() + dur;
        while tokio::time::Instant::now() < deadline {
            loop {
                match self.rx_event.try_recv() {
                    Ok(rpc::Event::Message(m)) => {
                        if pred(&m) {
                            return Some(m);
                        }
                    }
                    Ok(rpc::Event::DebugMessage(m)) => {
                        if pred(&m) {
                            return Some(m);
                        }
                    }
                    Err(_) => break, // 現時点で空
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
        None
    }

    /// 現在受信可能なイベントをすべて取り出す（非同期待機なし）。
    pub fn drain_available(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(ev) = self.rx_event.try_recv() {
            if let rpc::Event::Message(m) = ev {
                out.push(m);
            }
        }
        out
    }
}

impl Drop for Node {
    fn drop(&mut self) {}
}

/// 空きポートを確保して返す（:0 に bind して番号を読み取り即クローズ）。
pub fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// 接続トークンを生成（addr = 127.0.0.1:port を暗号化）。
pub fn connect_token(port: u16) -> String {
    crypto::encrypt_conninfo_to_hex(&format!("127.0.0.1:{}", port)).unwrap()
}

/// 実アドレスに生 TCP 接続（不正フレーム注入用）。
pub async fn raw_connect(addr: &str) -> std::io::Result<TcpStream> {
    TcpStream::connect(addr).await
}

/// 生ソケットへバイト列を送信。
pub async fn send_raw(stream: &mut TcpStream, bytes: &[u8]) {
    use tokio::io::AsyncWriteExt;
    let _ = stream.write_all(bytes).await;
    let _ = stream.flush().await;
}

/// シード付き xorshift PRNG（依存追加なし）。
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng {
            state: if seed == 0 { 0x9E3779B97F4A7C15 } else { seed },
        }
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
    pub fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.below(i + 1);
            v.swap(i, j);
        }
    }
}

/// 全ノードが接続を確立するのを待つ（HELLO 交換のための余裕）。
pub async fn settle(dur: Duration) {
    sleep(dur).await;
}
