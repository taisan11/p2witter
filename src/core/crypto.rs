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
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    hkdf,
    rand::{SecureRandom, SystemRandom},
    signature::{self, Ed25519KeyPair, KeyPair},
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

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
pub fn verify_ed25519(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), CryptoError> {
    let verifier = signature::UnparsedPublicKey::new(&signature::ED25519, public_key);
    verifier
        .verify(message, signature)
        .map_err(|_| CryptoError::Verify)
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

// デフォルトの 32バイト固定鍵（デモ用途・簡易用途）。
// ビルド時に環境変数 `P2WITTER_CONNINFO_KEY` に 64文字の HEX 文字列を設定すると
// 上書きされ、バイナリにその鍵が埋め込まれる（ネットワーク分離用）。
// 鍵を変更すると古いトークンは復号できなくなり、別ネットワークになる。
const DEFAULT_CONNINFO_KEY: [u8; 32] = [
    0x42, 0x95, 0xAE, 0x10, 0x2C, 0x7D, 0x3F, 0x81, 0x19, 0xA2, 0x5B, 0xCC, 0xD3, 0x0E, 0x77, 0x6A,
    0x91, 0x54, 0x23, 0x88, 0x0F, 0xDE, 0x63, 0x11, 0x90, 0xAB, 0xC4, 0x55, 0x66, 0xE1, 0x2D, 0x3C,
];

static CONNINFO_KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

/// 接続情報暗号化鍵を返す。
/// ビルド時に `P2WITTER_CONNINFO_KEY`（64文字HEX）が設定されていればそれを使用し、
/// それ以外は `DEFAULT_CONNINFO_KEY` を使用する。値はバイナリに埋め込まれる。
pub fn conninfo_key() -> [u8; 32] {
    *CONNINFO_KEY.get_or_init(|| {
        match option_env!("P2WITTER_CONNINFO_KEY") {
            Some(s) if !s.trim().is_empty() => match parse_key_hex(s.trim()) {
                Some(k) => k,
                None => DEFAULT_CONNINFO_KEY,
            },
            _ => DEFAULT_CONNINFO_KEY,
        }
    })
}

/// 64文字の HEX 文字列を [u8;32] に変換（不正なら None）
fn parse_key_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for i in 0..32 {
        let hi = hex_val(bytes[i * 2])?;
        let lo = hex_val(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// ネットワーク識別用の鍵ハッシュ (SHA-256(CONNINFO_KEY))。
/// HELLO 時に交換され、一致しないピアは同一ネットワークとみなさない。
pub fn network_key_hash() -> [u8; 32] {
    let key = conninfo_key();
    let digest = ring::digest::digest(&ring::digest::SHA256, &key);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// addr:port などの接続文字列を暗号化し、hex文字列トークンとして返す。
/// 形式: hex(nonce(12B) || ciphertext+tag)
pub fn encrypt_conninfo_to_hex(conn: &str) -> Result<String, CryptoError> {
    let key = LessSafeKey::new(
        UnboundKey::new(&aead::CHACHA20_POLY1305, &conninfo_key())
            .map_err(|_| CryptoError::Key)?,
    );
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes).map_err(|_| CryptoError::Rand)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = conn.as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::Encrypt)?;

    let mut out = Vec::with_capacity(12 + in_out.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&in_out);
    Ok(to_hex(&out))
}

/// hexトークンから接続文字列を復号
pub fn decrypt_conninfo_from_hex(token_hex: &str) -> Result<String, CryptoError> {
    let mut data = from_hex(token_hex)?;
    if data.len() < 12 + 16 {
        // nonce + 最小タグ
        return Err(CryptoError::Decrypt);
    }
    let (nonce_bytes, mut ciphertext) = data.split_at_mut(12);
    let key = LessSafeKey::new(
        UnboundKey::new(&aead::CHACHA20_POLY1305, &conninfo_key())
            .map_err(|_| CryptoError::Key)?,
    );
    let nonce =
        Nonce::assume_unique_for_key(nonce_bytes.try_into().map_err(|_| CryptoError::Decrypt)?);
    let plain = key
        .open_in_place(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|_| CryptoError::Decrypt)?;
    let s = std::str::from_utf8(plain).map_err(|_| CryptoError::Decrypt)?;
    Ok(s.to_string())
}

/// X25519 鍵ペアを生成 (DM 用の鍵交換用)
/// 戻り値: (秘密鍵 32B, 公開鍵 32B)
pub fn generate_x25519_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let priv_bytes = random_bytes(32)?;
    let priv_arr: [u8; 32] = priv_bytes
        .clone()
        .try_into()
        .map_err(|_| CryptoError::Key)?;
    let secret = X25519StaticSecret::from(priv_arr);
    let public = X25519PublicKey::from(&secret);
    Ok((priv_bytes, public.to_bytes().to_vec()))
}

/// ECDH の共有秘密から ChaCha20-Poly1305 用の 32B 鍵を導出 (HKDF-SHA256)
fn dm_kdf(shared: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"p2witter-dm-v1");
    let prk = salt.extract(shared);
    let okm = prk
        .expand(&[b"dm-chacha-key"], &aead::CHACHA20_POLY1305)
        .map_err(|_| CryptoError::Encrypt)?;
    let mut key = [0u8; 32];
    okm.fill(&mut key).map_err(|_| CryptoError::Encrypt)?;
    Ok(key)
}

/// DMペイロード暗号化 (ECIES 風)
///
/// 送信側が宛先ごとに生成した DM 用 X25519 秘密鍵 (`sender_dm_priv`) と
/// 宛先の X25519 公開鍵 (`recipient_x25519_pub`) で ECDH し、導出した鍵で暗号化。
/// フレーム形式: sender_dm_pub(32B) || nonce(12B) || ciphertext+tag
/// これにより、宛先以外は復号できない (中継・盗聴されても秘匿性を保つ)。
pub fn encrypt_dm_payload(
    recipient_x25519_pub: &[u8],
    sender_dm_priv: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let recipient_arr: [u8; 32] = recipient_x25519_pub
        .try_into()
        .map_err(|_| CryptoError::Key)?;
    let recipient_pub = X25519PublicKey::from(recipient_arr);
    let sender_arr: [u8; 32] = sender_dm_priv.try_into().map_err(|_| CryptoError::Key)?;
    let sender_secret = X25519StaticSecret::from(sender_arr);
    let shared = sender_secret.diffie_hellman(&recipient_pub);
    let key = dm_kdf(shared.as_bytes())?;
    let aead_key = LessSafeKey::new(
        UnboundKey::new(&aead::CHACHA20_POLY1305, &key).map_err(|_| CryptoError::Key)?,
    );
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes).map_err(|_| CryptoError::Rand)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plain.to_vec();
    aead_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::Encrypt)?;

    let sender_pub = X25519PublicKey::from(&sender_secret);
    let mut out = Vec::with_capacity(32 + 12 + in_out.len());
    out.extend_from_slice(&sender_pub.to_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&in_out);
    Ok(out)
}

/// DMペイロード復号
///
/// 受信側は自身の X25519 秘密鍵 (`recipient_dm_priv`) とフレーム内の送信者 DM 公開鍵で
/// ECDH し、同じ共有鍵を再現して復号する。
pub fn decrypt_dm_payload(recipient_dm_priv: &[u8], frame: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if frame.len() < 32 + 12 + 16 {
        return Err(CryptoError::Decrypt);
    }
    let (pub_bytes, rest) = frame.split_at(32);
    let (nonce_bytes, ciphertext) = rest.split_at(12);
    let pub_arr: [u8; 32] = pub_bytes.try_into().map_err(|_| CryptoError::Key)?;
    let sender_pub = X25519PublicKey::from(pub_arr);
    let priv_arr: [u8; 32] = recipient_dm_priv.try_into().map_err(|_| CryptoError::Key)?;
    let recipient_secret = X25519StaticSecret::from(priv_arr);
    let shared = recipient_secret.diffie_hellman(&sender_pub);
    let key = dm_kdf(shared.as_bytes())?;
    let aead_key = LessSafeKey::new(
        UnboundKey::new(&aead::CHACHA20_POLY1305, &key).map_err(|_| CryptoError::Key)?,
    );
    let nonce =
        Nonce::assume_unique_for_key(nonce_bytes.try_into().map_err(|_| CryptoError::Decrypt)?);
    let mut buf = ciphertext.to_vec();
    let plain = aead_key
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(plain.to_vec())
}

/// ホップごとのトランスポートセッション鍵導出 (static-static ECDH + HKDF-SHA256)。
///
/// 接続時に HELLO で交換済みの X25519 公開鍵（Ed25519 署名付き）を利用する。
/// 双方が同一の共有秘密を得るので、送信鍵/受信鍵を公開鍵の大小関係で決定的に
/// 割り当て、送信方向と受信方向で別鍵を使うことでナンス重複を避ける。
/// 戻り値: (送信鍵, 受信鍵)
pub fn derive_transport_keys(
    my_x25519_priv: &[u8],
    my_x25519_pub: &[u8],
    peer_x25519_pub: &[u8],
) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let my_arr: [u8; 32] = my_x25519_priv.try_into().map_err(|_| CryptoError::Key)?;
    let my_secret = X25519StaticSecret::from(my_arr);
    let peer_arr: [u8; 32] = peer_x25519_pub.try_into().map_err(|_| CryptoError::Key)?;
    let peer_pub = X25519PublicKey::from(peer_arr);
    let shared = my_secret.diffie_hellman(&peer_pub);

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"p2witter-transport-v1");
    let prk = salt.extract(shared.as_bytes());

    let mut lo = [0u8; 32];
    let mut hi = [0u8; 32];
    prk.expand(&[b"p2witter-transport-lo-v1"], &aead::CHACHA20_POLY1305)
        .map_err(|_| CryptoError::Encrypt)?
        .fill(&mut lo)
        .map_err(|_| CryptoError::Encrypt)?;
    prk.expand(&[b"p2witter-transport-hi-v1"], &aead::CHACHA20_POLY1305)
        .map_err(|_| CryptoError::Encrypt)?
        .fill(&mut hi)
        .map_err(|_| CryptoError::Encrypt)?;

    let send_is_lo = my_x25519_pub < peer_x25519_pub;
    if send_is_lo {
        Ok((lo, hi))
    } else {
        Ok((hi, lo))
    }
}

/// トランスポート用にプロトコルフレーム全体を ChaCha20-Poly1305 で暗号化。
/// 形式: nonce(12B) || ciphertext+tag
pub fn seal_transport(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let aead_key = LessSafeKey::new(
        UnboundKey::new(&aead::CHACHA20_POLY1305, key).map_err(|_| CryptoError::Key)?,
    );
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes).map_err(|_| CryptoError::Rand)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    aead_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::Encrypt)?;

    let mut out = Vec::with_capacity(12 + in_out.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&in_out);
    Ok(out)
}

/// トランスポート用に復号。形式は `seal_transport` と同じ。
pub fn open_transport(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < 12 + 16 {
        return Err(CryptoError::Decrypt);
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let aead_key = LessSafeKey::new(
        UnboundKey::new(&aead::CHACHA20_POLY1305, key).map_err(|_| CryptoError::Key)?,
    );
    let nonce =
        Nonce::assume_unique_for_key(nonce_bytes.try_into().map_err(|_| CryptoError::Decrypt)?);
    let mut buf = ciphertext.to_vec();
    let plain = aead_key
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(plain.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_keys_are_symmetric_and_direction_separated() {
        // A と B が互いの X25519 公開鍵を交換したとする
        let (a_priv, a_pub) = generate_x25519_keypair().unwrap();
        let (b_priv, b_pub) = generate_x25519_keypair().unwrap();

        let (a_tx, a_rx) = derive_transport_keys(&a_priv, &a_pub, &b_pub).unwrap();
        let (b_tx, b_rx) = derive_transport_keys(&b_priv, &b_pub, &a_pub).unwrap();

        // 送信鍵と受信鍵が対称（Aの送信 = Bの受信、Aの受信 = Bの送信）
        assert_eq!(a_tx, b_rx);
        assert_eq!(a_rx, b_tx);

        // 同一ペアの送信鍵と受信鍵は異なる（ナンス重複回避）
        assert_ne!(a_tx, a_rx);

        // 暗号化→復号ラウンドトリップ
        let sealed = seal_transport(&a_tx, b"hello hop").unwrap();
        assert_ne!(&sealed, b"hello hop");
        let opened = open_transport(&b_rx, &sealed).unwrap();
        assert_eq!(opened, b"hello hop");

        // 間違った鍵では復号できない
        assert!(open_transport(&a_rx, &sealed).is_err());
    }
}
