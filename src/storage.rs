use chrono::{Datelike, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sled::Db;
use std::sync::OnceLock;

static DB: OnceLock<Db> = OnceLock::new();

pub fn init_storage(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if DB.get().is_some() {
        return Ok(());
    }
    let db = sled::open(path)?;
    let _ = DB.set(db); // 既に初期化されていたら無視
    Ok(())
}

fn db_opt() -> Option<&'static Db> {
    DB.get()
}

fn date_string(ts_millis: u64) -> String {
    use chrono::{TimeZone, Utc};
    // ts is unix millis UTC
    let secs = (ts_millis / 1000) as i64;
    let dt = Utc
        .timestamp_opt(secs, ((ts_millis % 1000) * 1_000_000) as u32)
        .single()
        .unwrap();
    format!("{:04}{:02}{:02}", dt.year(), dt.month(), dt.day())
}

fn encode_count(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}
fn decode_count(b: &[u8]) -> u64 {
    if b.len() == 8 {
        u64::from_be_bytes(b.try_into().unwrap())
    } else {
        0
    }
}

/// 永続化する構造化メッセージ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRecord {
    pub ts_millis: u64,
    /// 受信(or ローカル保存)時刻
    pub recv_ts_millis: u64,
    pub kind: MsgKind,
    pub from_peer_id: Option<usize>,
    pub to_peer_id: Option<usize>,
    pub handle: Option<String>,
    pub text: String,
    pub signed_ok: Option<bool>,
}

/// メッセージの種類（最小限）
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MsgKind {
    Chat,
    Dm,
    System,
}

/// Append one message (ts|text) into sled. Maintains per-day counter and global index of dates.
pub fn append_message(ts_millis: u64, text: &str) {
    let Some(db) = db_opt() else {
        return;
    };
    let date = date_string(ts_millis);
    // counter key cnt:YYYYMMDD
    let cnt_key = format!("cnt:{}", date);
    let current = db
        .get(&cnt_key)
        .ok()
        .flatten()
        .map(|v| decode_count(&v))
        .unwrap_or(0);
    let msg_key = format!("{}{}", date, current); // e.g. 202511080
    let value = format!("{}|{}", ts_millis, text);
    let _ = db.insert(msg_key.as_bytes(), value.as_bytes());
    let next = encode_count(current + 1);
    let _ = db.insert(cnt_key.as_bytes(), &next);
    if current == 0 {
        // update index list of dates
        let idx_key = b"index";
        let mut dates: Vec<String> = db
            .get(idx_key)
            .ok()
            .flatten()
            .map(|v| {
                String::from_utf8_lossy(&v)
                    .split('\n')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();
        if !dates.iter().any(|d| d == &date) {
            dates.push(date.clone());
            dates.sort();
            let body = dates.join("\n");
            let _ = db.insert(idx_key, body.as_bytes());
        }
    }
    let _ = db.flush();
}

/// postcard で構造化して保存
pub fn store_structured(rec: &MessageRecord) -> Result<(), Box<dyn std::error::Error>> {
    let Some(db) = db_opt() else {
        return Ok(());
    };
    let date = date_string(rec.ts_millis);
    let cnt_key = format!("cnt:{}", date);
    let current = db
        .get(&cnt_key)
        .ok()
        .flatten()
        .map(|v| decode_count(&v))
        .unwrap_or(0);
    let msg_key = format!("{}{}", date, current);
    let data = postcard::to_allocvec(rec)?;
    db.insert(msg_key.as_bytes(), data)?;
    let next = encode_count(current + 1);
    db.insert(cnt_key.as_bytes(), &next)?;
    if current == 0 {
        let idx_key = b"index";
        let mut dates: Vec<String> = db
            .get(idx_key)
            .ok()
            .flatten()
            .map(|v| {
                String::from_utf8_lossy(&v)
                    .split('\n')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();
        if !dates.iter().any(|d| d == &date) {
            dates.push(date.clone());
            dates.sort();
            let body = dates.join("\n");
            db.insert(idx_key, body.as_bytes())?;
        }
    }
    db.flush()?;
    Ok(())
}

/// 1日の構造化メッセージを読み出し（古→新）
pub fn load_structured_day(date: &str) -> Vec<MessageRecord> {
    let Some(db) = db_opt() else {
        return Vec::new();
    };
    let cnt_key = format!("cnt:{}", date);
    let total = db
        .get(&cnt_key)
        .ok()
        .flatten()
        .map(|v| decode_count(&v))
        .unwrap_or(0);
    let mut out = Vec::new();
    for i in 0..total {
        let key = format!("{}{}", date, i);
        if let Ok(Some(val)) = db.get(key.as_bytes()) {
            if let Ok(rec) = postcard::from_bytes::<MessageRecord>(&val) {
                out.push(rec);
            } else {
                // 互換性: 旧フォーマット(ts|text)なら文字列として復元
                let s = String::from_utf8_lossy(&val).to_string();
                if let Some(pos) = s.find('|') {
                    let ts = s[..pos].parse::<u64>().unwrap_or(0);
                    let txt = s[pos + 1..].to_string();
                    out.push(MessageRecord {
                        ts_millis: ts,
                        recv_ts_millis: ts,
                        kind: MsgKind::System,
                        from_peer_id: None,
                        to_peer_id: None,
                        handle: None,
                        text: txt,
                        signed_ok: None,
                    });
                }
            }
        }
    }
    out
}

/// Get list of known dates (sorted ascending YYYYMMDD)
pub fn list_dates() -> Vec<String> {
    let Some(db) = db_opt() else {
        return Vec::new();
    };
    db.get(b"index")
        .ok()
        .flatten()
        .map(|v| {
            String::from_utf8_lossy(&v)
                .split('\n')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}
