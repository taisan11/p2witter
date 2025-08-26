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
};

#[derive(Debug)]
pub enum CryptoError {
    Rand,
    Key,
    Sign,
    Verify,
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