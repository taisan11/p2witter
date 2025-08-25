//! Binary protocol definitions (stand‑alone; not yet wired into `main.rs`).
//!
//! Format (little fixed header):
//!
//! Byte 0 : version (u8)
//! Byte 1 : kind    (u8)  (1=Chat, 2=Cmd (local only usually), 3=System (local), others=Unknown)
//! Bytes 2..6 : payload length (u32, network / big endian)
//! Bytes 6..(6+len) : payload raw bytes (UTF-8 for chat text)
//!
//! Multiple frames can be concatenated. A frame is complete when the buffer
//! contains at least 6 bytes header and header-declared payload length bytes.
//! A decoder accumulates partial bytes and yields `Message` objects.
//!
//! This file is not referenced yet from `main.rs`; add `mod protocol;` later
//! to integrate. All logic is self-contained so you can unit test after adding
//! the `mod` line (or moving into a library crate).

use std::fmt;

/// 現状 Chat のみをサポート (kind=1 固定)。将来拡張時に enum を再導入。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct MsgKind; // marker

impl MsgKind {
    pub const CHAT: u8 = 1;
}

/// A decoded protocol message.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub version: u8,
    // 将来の拡張余地: 今は kind 固定 (=1)
    pub payload: Vec<u8>,
}

#[allow(dead_code)]
impl Message {
    pub fn chat(text: &str) -> Self { Self { version: 1, payload: text.as_bytes().to_vec() } }
}

/// Errors that can occur during decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ProtocolError {
    /// Header present but length field is implausible (too large).
    LengthTooLarge(u32),
    /// Version not supported.
    UnsupportedVersion(u8),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::LengthTooLarge(l) => write!(f, "length too large: {}", l),
            ProtocolError::UnsupportedVersion(v) => write!(f, "unsupported version: {}", v),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Encode a message into owned bytes (single frame).
#[allow(dead_code)]
pub fn encode(msg: &Message) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + msg.payload.len());
    out.push(msg.version); // version
    out.push(MsgKind::CHAT); // kind (1)
    let len = msg.payload.len() as u32;
    out.extend_from_slice(&len.to_be_bytes()); // length (big endian)
    out.extend_from_slice(&msg.payload);
    out
}

/// Streaming decoder that can accept partial chunks and emit complete messages.
#[allow(dead_code)]
pub struct Decoder {
    buf: Vec<u8>,
    max_payload: u32,
}

#[allow(dead_code)]
impl Decoder {
    /// Create a decoder with a maximum allowed payload (for DoS protection).
    pub fn with_max_payload(max_payload: u32) -> Self {
        Self { buf: Vec::new(), max_payload }
    }

    /// Create a decoder with a default (512 KB) limit.
    pub fn new() -> Self { Self::with_max_payload(512 * 1024) }

    /// Feed raw bytes into the internal buffer.
    pub fn feed(&mut self, data: &[u8]) { self.buf.extend_from_slice(data); }

    /// Attempt to extract as many complete messages as currently possible.
    pub fn drain(&mut self) -> Result<Vec<Message>, ProtocolError> {
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 6 { break; } // not enough header
            let version = self.buf[0];
            if version != 1 { return Err(ProtocolError::UnsupportedVersion(version)); }
            let kind_byte = self.buf[1];
            if kind_byte != MsgKind::CHAT { return Err(ProtocolError::UnsupportedVersion(kind_byte)); }
            let len = u32::from_be_bytes([self.buf[2], self.buf[3], self.buf[4], self.buf[5]]);
            if len > self.max_payload { return Err(ProtocolError::LengthTooLarge(len)); }
            let needed = 6 + (len as usize);
            if self.buf.len() < needed { break; } // wait for more
            let payload = self.buf[6..needed].to_vec();
            // remove frame
            self.buf.drain(..needed);
            out.push(Message { version, payload });
        }
        Ok(out)
    }

    /// Returns current buffered (incomplete) size.
    pub fn buffered_len(&self) -> usize { self.buf.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let m = Message::chat("hello world");
        let bytes = encode(&m);
        let mut d = Decoder::new();
        d.feed(&bytes[..2]); // partial
        assert!(d.drain().unwrap().is_empty());
        d.feed(&bytes[2..]);
        let msgs = d.drain().unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, b"hello world");
    assert_eq!(msgs[0].version, 1);
    }

    #[test]
    fn multiple_frames_in_one_feed() {
        let a = encode(&Message::chat("A"));
        let b = encode(&Message::chat("B"));
        let mut d = Decoder::new();
        let mut joined = Vec::new(); joined.extend_from_slice(&a); joined.extend_from_slice(&b);
        d.feed(&joined);
        let msgs = d.drain().unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].payload, b"A");
        assert_eq!(msgs[1].payload, b"B");
    }

    // unknown kind test 削除（kind=1固定のため）
}
