//! Binary protocol with optional Ed25519 signature + public key.
//!
//! Frame layout (big endian for all u32):
//!  0: version (u8) =1
//!  1: kind (u8) =1 (Chat)
//!  2..6: payload length L (u32)
//!  6..10: public key length P (u32) (0 or 32 for Ed25519)
//! 10..14: signature length S (u32) (0 or 64 for Ed25519)
//! 14..(14+P): public key bytes
//! (14+P)..(14+P+S): signature bytes
//! (14+P+S)..(14+P+S+L): payload bytes (UTF-8 chat text)
//!
//! Signature (when present) is over: version || kind || payload_len(be) || payload bytes.
//! 公開鍵や署名サイズは署名対象外 (シンプル化)。

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
    pub payload: Vec<u8>,
    pub public_key: Option<Vec<u8>>, // 32 bytes when present
    pub signature: Option<Vec<u8>>,  // 64 bytes when present
}

#[allow(dead_code)]
impl Message {
    pub fn chat(text: &str) -> Self { Self { version: 1, payload: text.as_bytes().to_vec(), public_key: None, signature: None } }
    pub fn with_key_sig(mut self, pk: Vec<u8>, sig: Vec<u8>) -> Self { self.public_key = Some(pk); self.signature = Some(sig); self }
}

/// Errors that can occur during decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ProtocolError {
    /// Header present but length field is implausible (too large).
    LengthTooLarge(u32),
    /// Version not supported.
    UnsupportedVersion(u8),
    /// Signature verification failed
    BadSignature,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::LengthTooLarge(l) => write!(f, "length too large: {}", l),
            ProtocolError::UnsupportedVersion(v) => write!(f, "unsupported version: {}", v),
            ProtocolError::BadSignature => write!(f, "bad signature"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Encode a message into owned bytes (single frame).
#[allow(dead_code)]
pub fn encode(msg: &Message) -> Vec<u8> {
    let payload_len = msg.payload.len() as u32;
    let (pk_len, pk_bytes) = match &msg.public_key { Some(pk) => (pk.len() as u32, pk.as_slice()), None => (0u32, &[][..]) };
    let (sig_len, sig_bytes) = match &msg.signature { Some(sig) => (sig.len() as u32, sig.as_slice()), None => (0u32, &[][..]) };
    let mut out = Vec::with_capacity(14 + pk_bytes.len() + sig_bytes.len() + msg.payload.len());
    out.push(msg.version);
    out.push(MsgKind::CHAT);
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(&pk_len.to_be_bytes());
    out.extend_from_slice(&sig_len.to_be_bytes());
    out.extend_from_slice(pk_bytes);
    out.extend_from_slice(sig_bytes);
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
            if self.buf.len() < 14 { break; }
            let version = self.buf[0];
            if version != 1 { return Err(ProtocolError::UnsupportedVersion(version)); }
            let kind_byte = self.buf[1];
            if kind_byte != MsgKind::CHAT { return Err(ProtocolError::UnsupportedVersion(kind_byte)); }
            let payload_len = u32::from_be_bytes([self.buf[2], self.buf[3], self.buf[4], self.buf[5]]);
            if payload_len > self.max_payload { return Err(ProtocolError::LengthTooLarge(payload_len)); }
            let pk_len = u32::from_be_bytes([self.buf[6], self.buf[7], self.buf[8], self.buf[9]]);
            let sig_len = u32::from_be_bytes([self.buf[10], self.buf[11], self.buf[12], self.buf[13]]);
            let needed = 14 + pk_len as usize + sig_len as usize + payload_len as usize;
            if self.buf.len() < needed { break; }
            let mut cursor = 14;
            let pk = if pk_len > 0 { Some(self.buf[cursor..cursor+pk_len as usize].to_vec()) } else { None };
            cursor += pk_len as usize;
            let sig = if sig_len > 0 { Some(self.buf[cursor..cursor+sig_len as usize].to_vec()) } else { None };
            cursor += sig_len as usize;
            let payload = self.buf[cursor..cursor+payload_len as usize].to_vec();
            self.buf.drain(..needed);
            out.push(Message { version, payload, public_key: pk, signature: sig });
        }
        Ok(out)
    }

    /// Returns current buffered (incomplete) size.
    pub fn buffered_len(&self) -> usize { self.buf.len() }
}

/// 署名対象バイト列 (version, kind, payload_len, payload)
pub fn signing_bytes(msg: &Message) -> Vec<u8> {
    let mut v = Vec::with_capacity(6 + msg.payload.len());
    v.push(msg.version);
    v.push(MsgKind::CHAT);
    v.extend_from_slice(&(msg.payload.len() as u32).to_be_bytes());
    v.extend_from_slice(&msg.payload);
    v
}