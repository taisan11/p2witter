//! Chat メッセージ (kind=1) のコンストラクタとテスト。

use super::base::*;

impl Message {
    pub fn chat(text: &str, ts: u64) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            kind: MsgKind::CHAT,
            attenuation: 0,
            payload: text.as_bytes().to_vec(),
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
}
