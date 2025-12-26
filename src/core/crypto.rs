//! 簡易的なEd25519鍵生成・署名・検証ユーティリティ (ring使用)
//!
//! Cargo.toml に以下を追加:
//! ring = "0.17"
//!
//! 例:
//! let keys = generate_ed25519_keypair()?;
//! let sig = sign_ed25519(b"hello", &keys.pkcs8)?;
//! verify_ed25519(b"hello", &sig, &keys.public)?;
//!
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{self, Ed25519KeyPair, KeyPair},
    aead::{self, LessSafeKey, UnboundKey, Nonce, Aad},
};

#[derive(Debug)]
pub enum CryptoError {
    Rand,
    Key,
    Sign,
    Verify,
    Encrypt,
    Decrypt,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use CryptoError::*;
        write!(
            f,
            "{}",
            match self {
                Rand => "乱数生成に失敗",
                Key => "鍵操作に失敗",
                Sign => "署名に失敗",
                Verify => "検証に失敗",
                Encrypt => "暗号化に失敗",
                Decrypt => "復号に失敗",
            }
        )
    }
}
impl std::error::Error for CryptoError {}

/// 生成されたEd25519鍵ペア（PKCS#8秘密鍵と生の公開鍵）
pub struct Ed25519KeyPairMaterial {
    /// PKCS#8 (v2) 形式の秘密鍵 (そのまま保存可)
    pub pkcs8: Vec<u8>,
    /// 公開鍵 (32バイト)
    pub public: Vec<u8>,
}

/// Ed25519鍵ペアを生成
pub fn generate_ed25519_keypair() -> Result<Ed25519KeyPairMaterial, CryptoError> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| CryptoError::Rand)?;
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| CryptoError::Key)?;
    Ok(Ed25519KeyPairMaterial {
        pkcs8: pkcs8.as_ref().to_vec(),
        public: keypair.public_key().as_ref().to_vec(),
    })
}

/// Ed25519署名を作成
pub fn sign_ed25519(message: &[u8], pkcs8_private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8_private_key).map_err(|_| CryptoError::Key)?;
    let sig = keypair.sign(message);
    Ok(sig.as_ref().to_vec())
}

/// Ed25519署名を検証
pub fn verify_ed25519(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), CryptoError> {
    let verifier = signature::UnparsedPublicKey::new(&signature::ED25519, public_key);
    verifier.verify(message, signature).map_err(|_| CryptoError::Verify)
}

/// ランダムバイト列を生成 (鍵IDなどに利用)
pub fn random_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    let rng = SystemRandom::new();
    let mut buf = vec![0u8; len];
    rng.fill(&mut buf).map_err(|_| CryptoError::Rand)?;
    Ok(buf)
}

/// 簡易HEXエンコード
pub fn to_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// HEXデコード (小文字/大文字両対応)
pub fn from_hex(s: &str) -> Result<Vec<u8>, CryptoError> {
    if s.len() % 2 != 0 {
        return Err(CryptoError::Key);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_val(bytes[i]).ok_or(CryptoError::Key)?;
        let lo = hex_val(bytes[i + 1]).ok_or(CryptoError::Key)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---- 簡易接続情報暗号化（アプリ内埋め込み鍵を使用） ----

// 32バイト固定鍵（デモ用途・簡易用途）。実運用ではビルド時に差し替えるなど要配慮。
// ここでは定数値を例として埋め込み。変更すると古いトークンは復号できなくなります。
const CONNINFO_KEY: [u8; 32] = [
    0x42,0x95,0xAE,0x10,0x2C,0x7D,0x3F,0x81,
    0x19,0xA2,0x5B,0xCC,0xD3,0x0E,0x77,0x6A,
    0x91,0x54,0x23,0x88,0x0F,0xDE,0x63,0x11,
    0x90,0xAB,0xC4,0x55,0x66,0xE1,0x2D,0x3C,
];

/// addr:port などの接続文字列を暗号化し、hex文字列トークンとして返す。
/// 形式: hex(nonce(12B) || ciphertext+tag)
pub fn encrypt_conninfo_to_hex(conn: &str) -> Result<String, CryptoError> {
    let key = LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, &CONNINFO_KEY).map_err(|_| CryptoError::Key)?);
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes).map_err(|_| CryptoError::Rand)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = conn.as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out).map_err(|_| CryptoError::Encrypt)?;

    let mut out = Vec::with_capacity(12 + in_out.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&in_out);
    Ok(to_hex(&out))
}

/// hexトークンから接続文字列を復号
pub fn decrypt_conninfo_from_hex(token_hex: &str) -> Result<String, CryptoError> {
    let mut data = from_hex(token_hex)?;
    if data.len() < 12 + 16 { // nonce + 最小タグ
        return Err(CryptoError::Decrypt);
    }
    let (nonce_bytes, mut ciphertext) = data.split_at_mut(12);
    let key = LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, &CONNINFO_KEY).map_err(|_| CryptoError::Key)?);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().map_err(|_| CryptoError::Decrypt)?);
    let plain = key.open_in_place(nonce, Aad::empty(), &mut ciphertext).map_err(|_| CryptoError::Decrypt)?;
    let s = std::str::from_utf8(plain).map_err(|_| CryptoError::Decrypt)?;
    Ok(s.to_string())
}


/// DMペイロード暗号化: バイト列 -> 先頭12Bノンス + 暗号文+タグ
pub fn encrypt_dm_payload(plain: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // CONNINFO_KEY を共有鍵として流用（デモ用途）。
    // 形式は encrypt_conninfo_to_hex と同じ（ノンス12B先頭付与）。
    let key = LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, &CONNINFO_KEY).map_err(|_| CryptoError::Key)?);
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes).map_err(|_| CryptoError::Rand)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plain.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out).map_err(|_| CryptoError::Encrypt)?;

    let mut out = Vec::with_capacity(12 + in_out.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&in_out);
    Ok(out)
}

/// DMペイロード復号: 先頭12Bノンス + 暗号文+タグ -> 平文
pub fn decrypt_dm_payload(nonce_and_ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if nonce_and_ciphertext.len() < 12 + 16 { return Err(CryptoError::Decrypt); }
    let mut buf = nonce_and_ciphertext.to_vec();
    let (nonce_bytes, ciphertext) = buf.split_at_mut(12);
    let key = LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, &CONNINFO_KEY).map_err(|_| CryptoError::Key)?);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().map_err(|_| CryptoError::Decrypt)?);
    let plain = key.open_in_place(nonce, Aad::empty(), ciphertext).map_err(|_| CryptoError::Decrypt)?;
    Ok(plain.to_vec())
}
