//! DM (Direct Message) メッセージ (kind=2) のコンストラクタとテスト。
//!
//! DM の payload は ChaCha20-Poly1305 バイト列
//! (= nonce(12B) || ciphertext || tag(16B)) を想定するが、
//! プロトコル層では単なるバイト列として扱う。

use super::base::*;

impl Message {
    pub fn dm(text: &str, ts: u64) -> Self {
        Self::dm_bytes(text.as_bytes().to_vec(), ts)
    }

    pub fn dm_bytes(payload: Vec<u8>, ts: u64) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            kind: MsgKind::DM,
            attenuation: 0,
            payload,
            timestamp: ts,
            public_key: None,
            signature: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_encode_decode_dm_binary_payload() {
        let payload = vec![0, 159, 255, 1, 2, 3, 4];
        let msg = Message::dm_bytes(payload.clone(), 777);
        let encoded = encode(&msg);

        let mut decoder = Decoder::new();
        decoder.feed(&encoded);
        let decoded = decoder.drain().unwrap();

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].kind, MsgKind::DM);
        assert_eq!(decoded[0].payload, payload);
    }
}
