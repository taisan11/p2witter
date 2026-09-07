#[derive(Debug)]
pub enum Command {
    /// 待受開始。`public_host` は広告トークンに載せる外部アドレス（例: トンネル端点）。
    /// `None` なら config の `network.advertise_host`、さらに空なら `127.0.0.1` になる。
    Open { port: String, public_host: Option<String> },
    Connect(String),
    Handle(String),
    Close,
    Disconnect(String),
    PeerList,
    DM(String, String),
    Certs,
    Cert(String),
    Chat(String),
    /// トンネル経由で待受を開始。`provider` は "ngrok" / "serveo" 等。
    /// 成功すると自動で `Open { public_host: Some(<公開アドレス>) }` を実行する。
    Tunnel { provider: String, port: String },
    Shutdown,
}

#[derive(Debug)]
pub enum Event {
    Message(String),
    DebugMessage(String),
}
