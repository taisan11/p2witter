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

/// 任意のパスに値を挿入 (存在しなければ中間テーブルも作成) し、保存する。
pub fn upsert_value_and_save(path: &str, value: Value) -> Result<(), String> {
    {
        let lock = CONFIG.get().ok_or("config not initialized")?;
        let mut root = lock.write().map_err(|_| "config lock poisoned")?;
        let mut cur: &mut Table = &mut *root;
        let mut segments: Vec<&str> = path.split('.').collect();
        if segments.is_empty() { return Err("empty path".into()); }
        while segments.len() > 1 {
            let seg = segments.remove(0);
            let next = cur.entry(seg.to_string()).or_insert_with(|| Value::Table(Table::new()));
            match next {
                Value::Table(t) => { cur = t; }
                _ => { return Err(format!("segment '{}' is not a table", seg)); }
            }
        }
        let last = segments.remove(0);
        cur.insert(last.to_string(), value);
    }
    save().map_err(|e| format!("save failed: {}", e))
}

/// 設定を現在の内容で保存。
pub fn save() -> Result<(), std::io::Error> {
    if let Some(lock) = CONFIG.get() {
        let cfg = lock.read().expect("config lock poisoned");
        fs::write("./config.toml", cfg.to_string())?;
    }
    Ok(())
}