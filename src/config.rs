use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};
use toml::{Table, Value};

/// インスタンス単位で設定を保持する構造体。
///
/// 複数クライアントを1プロセス内で同時に起動するテスト/実験用に、
/// グローバルな `OnceLock` ではなく各インスタンスが固有の設定を持てるようにする。
/// バイナリ本体は後方互換のためのグローバルデフォルト (`global()`) を利用する。
pub struct Config {
    inner: RwLock<Table>,
    /// 保存先パス。`None` の場合はメモリのみ（ディスク書き込みを行わない）。
    path: Option<PathBuf>,
}

impl Clone for Config {
    fn clone(&self) -> Self {
        let tbl = self.inner.read().expect("config lock poisoned").clone();
        Config {
            inner: RwLock::new(tbl),
            path: self.path.clone(),
        }
    }
}

impl Config {
    /// パスを指定して読み込む。ファイルが存在しなければデフォルトを書き出してから読む。
    pub fn load(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
        let p = Path::new(path);
        let content = if p.exists() {
            fs::read_to_string(p)?
        } else {
            let default = default_toml_string();
            if let Some(parent) = p.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(p, &default)?;
            default
        };
        let table: Table = content.parse()?;
        Ok(Config {
            inner: RwLock::new(table),
            path: Some(p.to_path_buf()),
        })
    }

    /// 保存先を持たないメモリ専用設定（テスト用）。
    pub fn in_memory() -> Config {
        Config {
            inner: RwLock::new(default_table()),
            path: None,
        }
    }

    /// 既存の `Table` から構築（保存先なし）。
    pub fn from_table(table: Table) -> Config {
        Config {
            inner: RwLock::new(table),
            path: None,
        }
    }

    pub fn get_value(&self, path: &str) -> Option<Value> {
        let tbl = self.inner.read().expect("config lock poisoned");
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

    /// 任意のパスに値を挿入し、保存先があればディスクへ書き出す。
    pub fn upsert_value_and_save(&self, path: &str, value: Value) -> Result<(), String> {
        {
            let mut root = self.inner.write().expect("config lock poisoned");
            let mut cur: &mut Table = &mut *root;
            let mut segments: Vec<&str> = path.split('.').collect();
            if segments.is_empty() {
                return Err("empty path".into());
            }
            while segments.len() > 1 {
                let seg = segments.remove(0);
                let next = cur
                    .entry(seg.to_string())
                    .or_insert_with(|| Value::Table(Table::new()));
                match next {
                    Value::Table(t) => {
                        cur = t;
                    }
                    _ => {
                        return Err(format!("segment '{}' is not a table", seg));
                    }
                }
            }
            let last = segments.remove(0);
            cur.insert(last.to_string(), value);
        }
        if let Some(p) = &self.path {
            self.save_to(p)?;
        }
        Ok(())
    }

    pub fn is_debug(&self) -> bool {
        self.get_value("debug")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    fn save_to(&self, p: &Path) -> Result<(), String> {
        let cfg = self.inner.read().expect("config lock poisoned");
        fs::write(p, cfg.to_string()).map_err(|e| format!("save failed: {}", e))
    }
}

fn default_table() -> Table {
    let mut t = Table::new();
    t.insert("testconfig".into(), Value::String("kurowasa-nn".into()));
    t.insert("debug".into(), Value::Boolean(false));

    let mut network = Table::new();
    // /open で public-host を省略した際のフォールバック公開アドレス。
    // 空文字なら 127.0.0.1（ローカル/LAN）になる。
    network.insert("advertise_host".into(), Value::String(String::new()));
    t.insert("network".into(), Value::Table(network));

    let mut tunnel = Table::new();
    // 使用するトンネルプロバイダ（空なら未設定）。/tunnel で上書き可能。
    tunnel.insert("provider".into(), Value::String(String::new()));
    // ngrok の authtoken（任意）。空なら未指定。
    tunnel.insert("ngrok_authtoken".into(), Value::String(String::new()));
    t.insert("tunnel".into(), Value::Table(tunnel));

    t
}

fn default_toml_string() -> String {
    default_table().to_string()
}

// ---- バイナリ本体向けのグローバルデフォルト（後方互換） ----

static DEFAULT_CONFIG: OnceLock<Config> = OnceLock::new();

/// パスを指定してグローバルデフォルトを初期化。すでに初期化済みなら何もしない。
pub fn init_config_path(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if DEFAULT_CONFIG.get().is_some() {
        return Ok(());
    }
    let c = Config::load(path)?;
    let _ = DEFAULT_CONFIG.set(c);
    Ok(())
}

/// グローバルデフォルト設定への参照。
pub fn global() -> &'static Config {
    DEFAULT_CONFIG
        .get()
        .expect("config not initialized. call init_config_path first.")
}

fn with_global<T>(f: impl FnOnce(&'static Config) -> T) -> T {
    f(global())
}

/// 設定ファイルの `debug` フラグを簡単に取得するヘルパ
pub fn is_debug() -> bool {
    with_global(|c| c.is_debug())
}

pub fn get_value(path: &str) -> Option<Value> {
    with_global(|c| c.get_value(path))
}

/// 任意のパスに値を挿入 (存在しなければ中間テーブルも作成) し、保存してからディスクから再読み込みする。
pub fn upsert_value_and_save(path: &str, value: Value) -> Result<(), String> {
    let c = global();
    c.upsert_value_and_save(path, value)?;
    // 保存先ファイルから再読み込みしてメモリ上の CONFIG を更新する
    if let Some(p) = &c.path {
        let content = fs::read_to_string(p).map_err(|e| format!("reload read failed: {}", e))?;
        let table: Table = content
            .parse()
            .map_err(|e| format!("reload parse failed: {}", e))?;
        let mut root = c.inner.write().map_err(|_| "config lock poisoned")?;
        *root = table;
    }
    Ok(())
}

/// 設定を現在の内容で保存。
pub fn save() -> Result<(), std::io::Error> {
    if let Some(c) = DEFAULT_CONFIG.get() {
        if let Some(p) = &c.path {
            let cfg = c.inner.read().expect("config lock poisoned");
            fs::write(p, cfg.to_string())?;
        }
    }
    Ok(())
}
