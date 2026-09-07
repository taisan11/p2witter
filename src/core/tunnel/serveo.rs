//! serveo.net トンネル統合（生 TCP 転送）。
//!
//! `ssh -R 0:localhost:<port> serveo.net` を起動し、出力された
//! `Forwarding TCP connections from host:port` から公開アドレスを得る。

use std::process::Stdio;

use super::{read_public_addr, TunnelError, TunnelSession};
use tokio::process::Command;

pub async fn start(port: u16) -> Result<TunnelSession, TunnelError> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-R")
        .arg(format!("0:localhost:{}", port))
        .arg("serveo.net");
    // 対話プロンプト（known_hosts の yes/no、パスワード等）を抑制し、
    // ホスト鍵は初回のみ自動受け入れて保存する。これが無いとトンネルが
    // ブロックされる。
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("LogLevel=ERROR");
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(TunnelError::Spawn)?;

    let public_addr = read_public_addr(&mut child, |line| {
        // 例: "Forwarding TCP connections from abcd.serveo.net:44345"
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Forwarding TCP connections from ") {
            let addr = rest.split_whitespace().next().unwrap_or("").trim();
            if super::looks_like_addr(addr) {
                return Some(addr.to_string());
            }
        }
        None
    })
    .await?;

    Ok(TunnelSession { child, public_addr })
}
