use std::sync::{OnceLock, RwLock};
use std::fs;
use std::path::Path;
use toml::{Table, Value};

static CONFIG: OnceLock<RwLock<Table>> = OnceLock::new();

/// パスを指定して初期化。ファイルが存在しなければデフォルトを書き出してから読む。
/// すでに初期化済みなら何もしない。
pub fn init_config_path(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if CONFIG.get().is_some() { return Ok(()); }
    let p = Path::new(path);
    let content = if p.exists() {
        fs::read_to_string(p)?
    } else {
        let default = default_toml_string();
        if let Some(parent) = p.parent() { if !parent.as_os_str().is_empty() { fs::create_dir_all(parent)?; } }
        fs::write(p, &default)?;
        default
    };
    let table: Table = content.parse()?;
    let _ = CONFIG.set(RwLock::new(table));
    Ok(())
}

fn default_toml_string() -> String {
    // 最小のデフォルト値。必要に応じて拡張。
    // 例: デフォルトでサーバーポート2234、ユーザー名未設定など
    let mut t = Table::new();
    t.insert("testconfig".into(), Value::String("kurowasa-nn".into()));
    t.to_string()
}

pub fn config() -> std::sync::RwLockReadGuard<'static, Table> {
    CONFIG.get().expect("config not initialized. call init_config first.").read().expect("config lock poisoned")
}

pub fn get_value(path: &str) -> Option<Value> {
    let tbl = config();
    let mut cur: Option<&Value> = None;
    for (i, seg) in path.split('.').enumerate() {
        cur = if i == 0 {
            tbl.get(seg)
        } else {
            cur.and_then(|v| v.get(seg))
        };
        if cur.is_none() {
            return None;
        }
    }
    cur.cloned()
}

pub fn set_value(path: &str, value: Value) -> Result<(), String> {
    let mut tbl = CONFIG
        .get()
        .ok_or("config not initialized. call init_config first.")?
        .write()
        .map_err(|_| "config lock poisoned")?;
    let mut cur: &mut Table = &mut *tbl;
    let mut segments = path.split('.').peekable();
    while let Some(seg) = segments.next() {
        if segments.peek().is_none() {
            // 最後のセグメント
            if let Some(v) = cur.get_mut(seg) {
                *v = value;
                return Ok(());
            } else {
                return Err(format!("Key '{}' not found", seg));
            }
        } else {
            // 中間のセグメント
            if let Some(Value::Table(t)) = cur.get_mut(seg) {
                cur = t;
            } else {
                return Err(format!("Key '{}' not found or not a table", seg));
            }
        }
    }
    Err("Invalid path".into())
}

pub fn set_value_and_save(path: &str, value: Value) -> Result<(), String> {
    let result = set_value(path, value);
    if result.is_ok() {
        if let Some(lock) = CONFIG.get() {
            if let Ok(cfg) = lock.read() {
                if let Err(e) = fs::write("./config.toml", cfg.to_string()) {
                    return Err(format!("Failed to save config: {}", e));
                }
            } else {
                return Err("Failed to acquire read lock for saving".into());
            }
        }
    }
    result
}