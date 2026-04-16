#[derive(Debug)]
pub enum Command {
    Open(String),
    Connect(String),
    Handle(String),
    Close,
    Disconnect(String),
    PeerList,
    DM(String, String),
    Certs,
    Chat(String),
    Shutdown,
}

#[derive(Debug)]
pub enum Event {
    Message(String),
    DebugMessage(String),
}
