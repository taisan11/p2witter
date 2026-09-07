//! 任意の Tunnel サービスとの統合。
//!
//! 各プロバイダは `Tunnel` を実装し、ローカル `port` への転送を開始して
//! 外部から到達可能な `host:port` を返す。プロセスは `TunnelSession` が
//! 所有し、Drop 時に子プロセスを kill する。
//!
//! P2Witter は生 TCP プロトコルであるため、HTTP のみのトンネルは利用できない。
//! ここでは生 TCP 転送に対応する `ngrok tcp` と `serveo.net` を実装する。

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Child;

mod ngrok;
mod serveo;

#[derive(Debug)]
pub enum TunnelError {
    Spawn(std::io::Error),
    UnsupportedProvider(String),
    NoAddress,
    ProcessExited(String),
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelError::Spawn(e) => write!(f, "トンネル起動失敗: {}", e),
            TunnelError::UnsupportedProvider(p) => write!(f, "未対応のプロバイダ: {}", p),
            TunnelError::NoAddress => write!(f, "公開アドレスを取得できませんでした"),
            TunnelError::ProcessExited(s) => write!(f, "{}", s),
        }
    }
}

/// 起動中のトンネルセッション。Drop で子プロセスを終了する。
pub struct TunnelSession {
    child: Child,
    /// 外部から到達可能な `host:port`
    pub public_addr: String,
}

impl TunnelSession {
    pub fn public_addr(&self) -> &str {
        &self.public_addr
    }
}

impl Drop for TunnelSession {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// プロバイダ名からトンネルを起動し、公開アドレスを含むセッションを返す。
pub async fn start(provider: &str, port: u16) -> Result<TunnelSession, TunnelError> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "ngrok" => ngrok::start(port).await,
        "serveo" => serveo::start(port).await,
        other => Err(TunnelError::UnsupportedProvider(other.to_string())),
    }
}

/// 子プロセスの stdout を行ごとに読み、最初に `parse` が `Some` を返した
/// アドレスを返す。一定時間取得できない、あるいはプロセスが終了したら失敗。
async fn read_public_addr(
    child: &mut Child,
    parse: impl Fn(&str) -> Option<String>,
) -> Result<String, TunnelError> {
    let stdout = child
        .stdout
        .take()
        .ok_or(TunnelError::NoAddress)?;
    let mut reader = BufReader::new(stdout).lines();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(TunnelError::NoAddress);
        }
        if let Some(status) = child.try_wait().ok().flatten() {
            return Err(TunnelError::ProcessExited(format!(
                "トンネルプロセスが終了しました: {:?}",
                status
            )));
        }
        match tokio::time::timeout(std::time::Duration::from_millis(200), reader.next_line()).await {
            Ok(Ok(Some(line))) => {
                if let Some(addr) = parse(&line) {
                    return Ok(addr);
                }
            }
            Ok(Ok(None)) => return Err(TunnelError::NoAddress),
            Ok(Err(_)) => return Err(TunnelError::NoAddress),
            Err(_) => continue,
        }
    }
}

/// 公開アドレス（末尾に `:port` を含む）として妥当か。
fn looks_like_addr(s: &str) -> bool {
    s.split(':').count() >= 2 && !s.starts_with(':')
}
