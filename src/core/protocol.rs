//! Binary protocol with optional Ed25519 signature + public key (Chat & DM) + timestamp.
//!

//! Frame layout (big endian for all multi-byte integers):

//!  0:    version (u8) =1

//!  1:    kind (u8) =1 Chat, =2 DM

//!  2:    attenuation (u8)
//!  3..7: payload length L (u32)

//!  7..11: public key length P (u32) (0 or 32 for Ed25519)

//! 11..15: signature length S (u32) (0 or 64 for Ed25519)

//! 15..23: timestamp (u64) = UNIX millis (UTC)

//! 23..(23+P): public key bytes

//! (23+P)..(23+P+S): signature bytes

//! (23+P+S)..(23+P+S+L): payload bytes (UTF-8 chat text)

//! (23+P+S)..(23+P+S+L): payload bytes

//!     - Chat(kind=1): UTF-8 text
//!     - DM(kind=2):  ChaCha20-Poly1305 bytes = nonce(12B) || ciphertext || tag(16B)
//!
//! Signature (when present) is over: version || kind || payload_len(be) || timestamp || payload bytes.
//! 公開鍵や署名サイズは署名対象外 (シンプル化)。

//! Signature (when present) is over: version || kind || payload_len(be) || timestamp || payload bytes.
//! 公開鍵や署名サイズは署名対象外 (シンプル化)。

//!
//! Signature (when present) is over: version || kind || payload_len(be) || payload bytes.
//! 公開鍵や署名サイズは署名対象外 (シンプル化)。

use std::fmt;

/// kind 定義 (簡易: 定数)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct MsgKind; // marker

impl MsgKind {
    pub const CHAT: u8 = 1;
    pub const DM: u8 = 2; // ダイレクトメッセージ
    pub const HELLO: u8 = 3; // 接続直後の公開鍵交換
    pub const DISCONNECT: u8 = 4; // 切断通知（理由IDをpayloadに格納）
}

/// A decoded protocol message.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub version: u8,
    pub kind: u8,
    pub attenuation: u8,
    pub payload: Vec<u8>,
    pub timestamp: u64,
    pub public_key: Option<Vec<u8>>, // 32 bytes when present
    pub signature: Option<Vec<u8>>,  // 64 bytes when present
}

impl Message {
    pub fn chat(text: &str, ts: u64) -> Self {
        Self {
            version: 1,
            kind: MsgKind::CHAT,
            attenuation: 0,
            payload: text.as_bytes().to_vec(),
            timestamp: ts,
            public_key: None,
            signature: None,
        }
    }

    pub fn dm(text: &str, ts: u64) -> Self {
        Self {
            version: 1,
            kind: MsgKind::DM,
            attenuation: 0,
            payload: text.as_bytes().to_vec(),
            timestamp: ts,
            public_key: None,
            signature: None,
        }
    }

    // pub fn hello(ts: u64) -> Self { Self { version: 1, kind: MsgKind::HELLO, attenuation: 0, payload: Vec::new(), timestamp: ts, public_key: None, signature: None } }

    pub fn disconnect(ts: u64, reason_id: u32) -> Self {
        let mut p = Vec::with_capacity(4);

        p.extend_from_slice(&reason_id.to_be_bytes());

        Self {
            version: 1,
            kind: MsgKind::DISCONNECT,
            attenuation: 0,
            payload: p,
            timestamp: ts,
            public_key: None,
            signature: None,
        }
    }

    pub fn hello(ts: u64, handle: &str) -> Self {
        Self {
            version: 1,
            kind: MsgKind::HELLO,
            attenuation: 0,
            payload: handle.as_bytes().to_vec(),
            timestamp: ts,
            public_key: None,
            signature: None,
        }
    }

    pub fn with_key_sig(mut self, pk: Vec<u8>, sig: Vec<u8>) -> Self {
        self.public_key = Some(pk);
        self.signature = Some(sig);
        self
    }

    pub fn with_key(mut self, pk: Vec<u8>) -> Self {
        self.public_key = Some(pk);
        self
    }
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

    /// Attenuation value is abnormal
    BadAttenuation(u8),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::LengthTooLarge(l) => write!(f, "length too large: {}", l),

            ProtocolError::UnsupportedVersion(v) => write!(f, "unsupported version: {}", v),

            ProtocolError::BadSignature => write!(f, "bad signature"),

            ProtocolError::BadAttenuation(a) => write!(f, "bad attenuation: {}", a),
        }
    }
}

impl std::error::Error for ProtocolError {}

pub fn encode(msg: &Message) -> Vec<u8> {
    let payload_len = msg.payload.len() as u32;

    let (pk_len, pk_bytes) = match &msg.public_key {
        Some(pk) => (pk.len() as u32, pk.as_slice()),
        None => (0u32, &[][..]),
    };

    let (sig_len, sig_bytes) = match &msg.signature {
        Some(sig) => (sig.len() as u32, sig.as_slice()),
        None => (0u32, &[][..]),
    };

    let mut out = Vec::with_capacity(23 + pk_bytes.len() + sig_bytes.len() + msg.payload.len());

    out.push(msg.version);

    out.push(msg.kind);

    out.push(msg.attenuation);
    out.extend_from_slice(&payload_len.to_be_bytes());

    out.extend_from_slice(&pk_len.to_be_bytes());

    out.extend_from_slice(&sig_len.to_be_bytes());

    out.extend_from_slice(&msg.timestamp.to_be_bytes());

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
        Self {
            buf: Vec::new(),
            max_payload,
        }
    }

    /// Create a decoder with a default (512 KB) limit.
    pub fn new() -> Self {
        Self::with_max_payload(512 * 1024)
    }

    /// Feed raw bytes into the internal buffer.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn drain(&mut self) -> Result<Vec<Message>, ProtocolError> {
        let mut out = Vec::new();

        loop {
            if self.buf.len() < 23 {
                break;
            }

            let version = self.buf[0];

            if version != 1 {
                return Err(ProtocolError::UnsupportedVersion(version));
            }

            let kind_byte = self.buf[1];

            if kind_byte != MsgKind::CHAT
                && kind_byte != MsgKind::DM
                && kind_byte != MsgKind::HELLO
                && kind_byte != MsgKind::DISCONNECT
            {
                return Err(ProtocolError::UnsupportedVersion(kind_byte));
            }

            let attenuation = self.buf[2];

            if attenuation > 50 {
                return Err(ProtocolError::BadAttenuation(attenuation));
            }
            let payload_len =
                u32::from_be_bytes([self.buf[3], self.buf[4], self.buf[5], self.buf[6]]);

            if payload_len > self.max_payload {
                return Err(ProtocolError::LengthTooLarge(payload_len));
            }

            let pk_len = u32::from_be_bytes([self.buf[7], self.buf[8], self.buf[9], self.buf[10]]);

            let sig_len =
                u32::from_be_bytes([self.buf[11], self.buf[12], self.buf[13], self.buf[14]]);

            let timestamp = u64::from_be_bytes([
                self.buf[15],
                self.buf[16],
                self.buf[17],
                self.buf[18],
                self.buf[19],
                self.buf[20],
                self.buf[21],
                self.buf[22],
            ]);

            let needed = 23 + pk_len as usize + sig_len as usize + payload_len as usize;

            if self.buf.len() < needed {
                break;
            }

            let mut cursor = 23;
            let pk = if pk_len > 0 {
                Some(self.buf[cursor..cursor + pk_len as usize].to_vec())
            } else {
                None
            };

            cursor += pk_len as usize;

            let sig = if sig_len > 0 {
                Some(self.buf[cursor..cursor + sig_len as usize].to_vec())
            } else {
                None
            };

            cursor += sig_len as usize;

            let payload = self.buf[cursor..cursor + payload_len as usize].to_vec();

            self.buf.drain(..needed);

            out.push(Message {
                version,
                kind: kind_byte,
                attenuation,
                payload,
                timestamp,
                public_key: pk,
                signature: sig,
            });
        }

        Ok(out)
    }

    /// Returns current buffered (incomplete) size.
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }
}

pub fn signing_bytes(msg: &Message) -> Vec<u8> {
    let mut v = Vec::with_capacity(14 + msg.payload.len());

    v.push(msg.version);

    v.push(msg.kind);

    v.extend_from_slice(&(msg.payload.len() as u32).to_be_bytes());

    v.extend_from_slice(&msg.timestamp.to_be_bytes());

    v.extend_from_slice(&msg.payload);

    v
}

/// 切断理由IDの取得（payload が4バイトである必要）。
#[allow(dead_code)]
pub fn disconnect_reason_id(msg: &Message) -> Option<u32> {
    if msg.kind != MsgKind::DISCONNECT {
        return None;
    }
    if msg.payload.len() < 4 {
        return None;
    }
    Some(u32::from_be_bytes([
        msg.payload[0],
        msg.payload[1],
        msg.payload[2],
        msg.payload[3],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_chat_message() {
        let msg = Message::chat("Hello, P2Witter!", 1234567890);
        let encoded = encode(&msg);
        
        let mut decoder = Decoder::new();
        decoder.feed(&encoded);
        let decoded = decoder.drain().unwrap();
        
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].payload, msg.payload);
        assert_eq!(decoded[0].kind, MsgKind::CHAT);
        assert_eq!(decoded[0].timestamp, 1234567890);
    }

    #[test]
    fn test_encode_decode_dm_message() {
        let msg = Message::dm("Secret message", 9876543210);
        let encoded = encode(&msg);
        
        let mut decoder = Decoder::new();
        decoder.feed(&encoded);
        let decoded = decoder.drain().unwrap();
        
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].kind, MsgKind::DM);
        assert_eq!(decoded[0].payload, msg.payload);
    }

    #[test]
    fn test_encode_decode_with_signature() {
        let mut msg = Message::chat("Signed message", 1111111111);
        msg.public_key = Some(vec![1u8; 32]);
        msg.signature = Some(vec![2u8; 64]);
        
        let encoded = encode(&msg);
        
        let mut decoder = Decoder::new();
        decoder.feed(&encoded);
        let decoded = decoder.drain().unwrap();
        
        assert_eq!(decoded[0].public_key.as_ref().unwrap().len(), 32);
        assert_eq!(decoded[0].signature.as_ref().unwrap().len(), 64);
        assert_eq!(decoded[0].payload, msg.payload);
    }

    #[test]
    fn test_partial_message_buffering() {
        let msg = Message::chat("Test", 100);
        let encoded = encode(&msg);
        
        let mut decoder = Decoder::new();
        
        // 分割して送信（ヘッダの途中まで）
        decoder.feed(&encoded[..10]);
        assert_eq!(decoder.drain().unwrap().len(), 0); // まだ完全でない
        
        // 残りを送信
        decoder.feed(&encoded[10..]);
        let decoded = decoder.drain().unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].payload, msg.payload);
    }

    #[test]
    fn test_multiple_messages_in_stream() {
        let msg1 = Message::chat("First", 111);
        let msg2 = Message::chat("Second", 222);
        
        let mut encoded = encode(&msg1);
        encoded.extend_from_slice(&encode(&msg2));
        
        let mut decoder = Decoder::new();
        decoder.feed(&encoded);
        let decoded = decoder.drain().unwrap();
        
        assert_eq!(decoded.len(), 2);
        assert_eq!(String::from_utf8_lossy(&decoded[0].payload), "First");
        assert_eq!(String::from_utf8_lossy(&decoded[1].payload), "Second");
    }

    #[test]
    fn test_hello_message() {
        let msg = Message::hello(5000, "@alice");
        let encoded = encode(&msg);
        
        let mut decoder = Decoder::new();
        decoder.feed(&encoded);
        let decoded = decoder.drain().unwrap();
        
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].kind, MsgKind::HELLO);
        assert_eq!(String::from_utf8_lossy(&decoded[0].payload), "@alice");
    }

    #[test]
    fn test_disconnect_message() {
        let msg = Message::disconnect(6000, 42);
        let encoded = encode(&msg);
        
        let mut decoder = Decoder::new();
        decoder.feed(&encoded);
        let decoded = decoder.drain().unwrap();
        
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].kind, MsgKind::DISCONNECT);
        
        let reason = disconnect_reason_id(&decoded[0]);
        assert_eq!(reason, Some(42));
    }

    #[test]
    fn test_malformed_version() {
        let mut invalid = vec![99u8]; // invalid version
        invalid.extend_from_slice(&[0u8; 22]);
        
        let mut decoder = Decoder::new();
        decoder.feed(&invalid);
        let result = decoder.drain();
        
        assert!(matches!(result, Err(ProtocolError::UnsupportedVersion(99))));
    }

    #[test]
    fn test_length_too_large() {
        let mut msg = vec![1u8, 1u8, 0u8]; // version, kind, attenuation
        msg.extend_from_slice(&(1u32 << 30).to_be_bytes()); // payload_len: 超大サイズ
        msg.extend_from_slice(&0u32.to_be_bytes()); // pk_len: 0
        msg.extend_from_slice(&0u32.to_be_bytes()); // sig_len: 0
        msg.extend_from_slice(&0u64.to_be_bytes()); // timestamp: 0
        
        let mut decoder = Decoder::new();
        decoder.feed(&msg);
        let result = decoder.drain();
        
        assert!(matches!(result, Err(ProtocolError::LengthTooLarge(_))));
    }

    #[test]
    fn test_bad_attenuation() {
        let mut msg = vec![1u8, 1u8, 99u8]; // version, kind, bad attenuation (>50)
        msg.extend_from_slice(&[0u8; 20]);
        
        let mut decoder = Decoder::new();
        decoder.feed(&msg);
        let result = decoder.drain();
        
        assert!(matches!(result, Err(ProtocolError::BadAttenuation(99))));
    }

    #[test]
    fn test_signing_bytes() {
        let msg = Message::chat("test payload", 9999);
        let sig_bytes = signing_bytes(&msg);
        
        // 署名バイト列は: version(1) + kind(1) + payload_len(4) + timestamp(8) + payload
        let expected_len = 1 + 1 + 4 + 8 + 12; // "test payload"は12文字
        assert_eq!(sig_bytes.len(), expected_len);
        
        // バージョン確認
        assert_eq!(sig_bytes[0], 1);
        // kind確認
        assert_eq!(sig_bytes[1], MsgKind::CHAT);
    }

    #[test]
    fn test_attenuation_in_message() {
        let mut msg = Message::chat("Attenuated", 7777);
        msg.attenuation = 25;
        
        let encoded = encode(&msg);
        let mut decoder = Decoder::new();
        decoder.feed(&encoded);
        let decoded = decoder.drain().unwrap();
        
        assert_eq!(decoded[0].attenuation, 25);
    }

    #[test]
    fn test_empty_payload() {
        let msg = Message::chat("", 1000);
        let encoded = encode(&msg);
        
        let mut decoder = Decoder::new();
        decoder.feed(&encoded);
        let decoded = decoder.drain().unwrap();
        
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].payload.len(), 0);
    }

    #[test]
    fn test_large_payload() {
        let large_text = "x".repeat(50000);
        let msg = Message::chat(&large_text, 2000);
        let encoded = encode(&msg);
        
        let mut decoder = Decoder::new();
        decoder.feed(&encoded);
        let decoded = decoder.drain().unwrap();
        
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].payload.len(), 50000);
    }

    #[test]
    fn test_message_without_signature() {
        let msg = Message::chat("No signature", 3000);
        let encoded = encode(&msg);
        
        let mut decoder = Decoder::new();
        decoder.feed(&encoded);
        let decoded = decoder.drain().unwrap();
        
        assert_eq!(decoded[0].public_key, None);
        assert_eq!(decoded[0].signature, None);
    }

    #[test]
    fn test_incremental_feeding() {
        let msg1 = Message::chat("First", 111);
        let msg2 = Message::chat("Second", 222);
        
        let mut encoded = encode(&msg1);
        encoded.extend_from_slice(&encode(&msg2));
        
        let mut decoder = Decoder::new();
        
        // 1バイトずつ送信
        for byte in &encoded {
            decoder.feed(&[*byte]);
        }
        
        let decoded = decoder.drain().unwrap();
        assert_eq!(decoded.len(), 2);
    }

    #[test]
    fn test_with_key_sig_builder() {
        let msg = Message::chat("Builder test", 4000)
            .with_key(vec![3u8; 32])
            .with_key_sig(vec![4u8; 32], vec![5u8; 64]);
        
        let encoded = encode(&msg);
        let mut decoder = Decoder::new();
        decoder.feed(&encoded);
        let decoded = decoder.drain().unwrap();
        
        assert_eq!(decoded[0].public_key.as_ref().unwrap().len(), 32);
        assert_eq!(decoded[0].signature.as_ref().unwrap().len(), 64);
    }

    #[test]
    fn test_timestamp_preservation() {
        let ts = 1701234567890u64;
        let msg = Message::chat("Timestamp test", ts);
        let encoded = encode(&msg);
        
        let mut decoder = Decoder::new();
        decoder.feed(&encoded);
        let decoded = decoder.drain().unwrap();
        
        assert_eq!(decoded[0].timestamp, ts);
    }

    #[test]
    fn test_all_message_kinds() {
        let chat = Message::chat("Chat", 1000);
        let dm = Message::dm("DM", 2000);
        let hello = Message::hello(3000, "@user");
        let disconnect = Message::disconnect(4000, 1);
        
        assert_eq!(chat.kind, MsgKind::CHAT);
        assert_eq!(dm.kind, MsgKind::DM);
        assert_eq!(hello.kind, MsgKind::HELLO);
        assert_eq!(disconnect.kind, MsgKind::DISCONNECT);
    }

    #[test]
    fn test_decoder_buffer_state() {
        let msg = Message::chat("Buffer", 5000);
        let encoded = encode(&msg);
        
        let mut decoder = Decoder::new();
        assert_eq!(decoder.buffered_len(), 0);
        
        decoder.feed(&encoded[..10]);
        assert_eq!(decoder.buffered_len(), 10);
        
        decoder.feed(&encoded[10..]);
        assert!(decoder.buffered_len() > 0); // Before drain
        
        let _ = decoder.drain();
        assert_eq!(decoder.buffered_len(), 0); // After drain
    }
}
