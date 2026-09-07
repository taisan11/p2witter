//! ngrok トンネル統合（生 TCP 転送）。
//!
//! `ngrok tcp <port>` を起動し、出力された `tcp://host:port` から公開アドレスを得る。

use std::process::Stdio;

use super::{read_public_addr, TunnelError, TunnelSession};
use crate::config;
use tokio::process::Command;

pub async fn start(port: u16) -> Result<TunnelSession, TunnelError> {
    let authtoken = config::get_value("tunnel.ngrok_authtoken")
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();

    let mut cmd = Command::new("ngrok");
    cmd.arg("tcp").arg(port.to_string());
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    if !authtoken.is_empty() {
        cmd.arg("--authtoken").arg(authtoken);
    }

    let mut child = cmd.spawn().map_err(TunnelError::Spawn)?;

    let public_addr = read_public_addr(&mut child, |line| {
        // 例: "Forwarding tcp://0.tcp.ngrok.io:12345 -> localhost:8080"
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Forwarding tcp://") {
            let addr = rest.split(" ->").next().unwrap_or("").trim();
            if super::looks_like_addr(addr) {
                return Some(addr.to_string());
            }
        }
        None
    })
    .await?;

    Ok(TunnelSession { child, public_addr })
}
