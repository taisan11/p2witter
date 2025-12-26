#[derive(Debug)]
pub enum Command {
    Open(String),
    Connect(String),
    Handle(String),
    // Close and disconnect all
    Shutdown,
    Close,
    Disconnect(String),
    PeerList,
    DM(String, String),
    Certs,
    Chat(String),
}

#[derive(Debug)]
pub enum Event {
    Message(String),
    DebugMessage(String),
}
