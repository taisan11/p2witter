use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self};
use std::time::Duration;
mod protocol;
mod config;
mod crypto;

fn current_unix_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

// コマンド仕様（説明・使い方）
#[derive(Clone, Copy)]
struct CommandSpec { name: &'static str, description: &'static str, usage: &'static str }
const COMMANDS: &[CommandSpec] = &[
    CommandSpec { name: "/help", description: "コマンド一覧または詳細を表示", usage: "/help [name]" },
    CommandSpec { name: "/open", description: "ローカルで待受を開始し、トークンを表示", usage: "/open <port>" },
    CommandSpec { name: "/close", description: "待受を終了", usage: "/close" },
    CommandSpec { name: "/connect", description: "トークンで接続", usage: "/connect <token>" },
    CommandSpec { name: "/disconnect", description: "接続を切断", usage: "/disconnect <id>" },
    CommandSpec { name: "/peers", description: "接続中のピア一覧を表示", usage: "/peers" },
    CommandSpec { name: "/certs", description: "ピア証明書（公開鍵）一覧を表示", usage: "/certs" },
    CommandSpec { name: "/cert", description: "指定ピアの公開鍵詳細を表示", usage: "/cert <id>" },
    CommandSpec { name: "/dm", description: "指定ピアにダイレクトメッセージを送信", usage: "/dm <to_id> <message>" },
    CommandSpec { name: "/msg", description: "全体にメッセージを送信", usage: "/msg <message>" },
    CommandSpec { name: "/handle", description: "自分のハンドル名を設定（@から始まり80文字未満）", usage: "/handle @name" },
    CommandSpec { name: "/init", description: "署名鍵を生成して保存", usage: "/init" },
    CommandSpec { name: "/exit", description: "アプリケーションを終了", usage: "/exit" },
];
fn find_command(name: &str) -> Option<&'static CommandSpec> { COMMANDS.iter().find(|c| c.name == name) }

// 表示桁（全角=2, 半角=1 等）を考慮して安全に切り詰める
fn display_width(s: &str) -> usize { unicode_width::UnicodeWidthStr::width(s) }
fn truncate_display(s: &str, max_cols: usize) -> String {
    use unicode_width::UnicodeWidthChar;
    if display_width(s) <= max_cols { return s.to_string(); }
    let mut cols = 0usize;
    let mut out = String::new();
    for ch in s.chars() {
        let w = UnicodeWidthChar::width(ch).unwrap_or(0);
        if cols + w > max_cols { break; }
        out.push(ch);
        cols += w;
    }
    out
}

// 末尾側（右端側）を優先して max_cols に収まる部分だけ取り出す（表示幅ベース）
fn take_last_display(s: &str, max_cols: usize) -> String {
    use unicode_width::UnicodeWidthChar;
    if display_width(s) <= max_cols { return s.to_string(); }
    let mut cols = 0usize;
    let mut rev: Vec<char> = Vec::new();
    for ch in s.chars().rev() {
        let w = UnicodeWidthChar::width(ch).unwrap_or(0);
        if cols + w > max_cols { break; }
        rev.push(ch);
        cols += w;
    }
    rev.into_iter().rev().collect()
}

// 文字インデックスで左右に分割（安全な UTF-8 境界）
fn split_at_char(s: &str, idx: usize) -> (String, String) {
    let total = s.chars().count();
    let idx = idx.min(total);
    let mut it = s.chars();
    let left: String = it.by_ref().take(idx).collect();
    let right: String = it.collect();
    (left, right)
}

// 署名付きチャット送信 (全体ブロードキャスト) - 鍵必須
fn build_signed_chat(text: &str, pkcs8: &[u8], pubk: &[u8]) -> Option<protocol::Message> {
    let mut m = protocol::Message::chat(text, current_unix_millis());
    if let Ok(sig) = crypto::sign_ed25519(&protocol::signing_bytes(&m), pkcs8) { m = m.with_key_sig(pubk.to_vec(), sig); Some(m) } else { None }
}
// 署名付きDM
fn build_signed_dm(text: &str, pkcs8: &[u8], pubk: &[u8]) -> Option<protocol::Message> {
    let ts = current_unix_millis();
    let ct = match crypto::encrypt_dm_payload(text.as_bytes()) { Ok(ct) => ct, Err(_) => return None };
    let mut m = protocol::Message::dm("", ts);
    m.payload = ct;
    if let Ok(sig) = crypto::sign_ed25519(&protocol::signing_bytes(&m), pkcs8) { m = m.with_key_sig(pubk.to_vec(), sig); Some(m) } else { None }
}

// 署名付きHELLO（ハンドル付き）
fn build_signed_hello(handle: &str, pkcs8: &[u8], pubk: &[u8]) -> Option<protocol::Message> {
    let mut m = protocol::Message::hello_with_handle(current_unix_millis(), handle);
    if let Ok(sig) = crypto::sign_ed25519(&protocol::signing_bytes(&m), pkcs8) { m = m.with_key_sig(pubk.to_vec(), sig); Some(m) } else { None }
}

fn main() {
    // ---- 初期セットアップ ----
    let (tx_to_main, rx_from_threads) = mpsc::channel::<String>();
    let mut active_thread_tx: Option<Sender<String>> = None;
    let mut active_thread_handle: Option<thread::JoinHandle<()>> = None;
    if let Err(e) = config::init_config_path("./config.toml") { eprintln!("設定初期化に失敗: {e}"); }

    // TUI 状態
    let mut messages: Vec<String> = Vec::new();
    let mut input = String::new();
    let mut running = true;
    // ハンドル（@から始まり80文字未満）: 必須（デフォルト廃止）
    let mut handle: String = config::get_value("user.handle")
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();

    use crossterm::{execute, event};
    use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode};
    use crossterm::event::{Event, KeyCode, KeyModifiers, KeyEvent, KeyEventKind, EnableMouseCapture, DisableMouseCapture};

    enable_raw_mode().expect("raw mode に移行できません");
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).ok();
    // 差分描画用状態と関数 + スクロール/履歴状態 + ステータスバー
    struct DrawState { last_msg_len: usize, last_input_len: usize, last_cursor_pos: usize, force_full: bool }
    impl DrawState { fn new() -> Self { Self { last_msg_len: 0, last_input_len: 0, last_cursor_pos: 0, force_full: true } } }
    fn redraw_full(stdout: &mut io::Stdout, messages: &Vec<String>, scroll_offset: usize, status_msg: &str) -> (u16,u16) {
        use crossterm::{terminal, queue, cursor};
        use crossterm::terminal::{Clear, ClearType};
    use crossterm::style::{self};
        let (w, h) = terminal::size().unwrap_or((80,24));
        let safe_w = w.saturating_sub(1) as usize; // 末尾1桁は未使用にして自動折返しを回避
        let input_row = h.saturating_sub(1); // 最下行
    // メッセージ領域の高さは後続の view_h で計算
        // スクロールオフセット: 0 が最新。offset が増えると過去方向
    // 旧カウントは flat_lines で再計算するため削除
        // 画面全消去は避けステータス+メッセージ領域のみクリア
        queue!(stdout, cursor::Hide).ok();
        // '\n' を実際の改行として扱い、行ごとに表示するために平坦化
        let mut flat_lines: Vec<String> = Vec::new();
        for msg in messages.iter() {
            for part in msg.split('\n') {
                let mut s = part.to_string();
                if display_width(&s) > safe_w { s = truncate_display(&s, safe_w); }
                flat_lines.push(s);
            }
        }
        let total = flat_lines.len();
        let view_h = if input_row > 1 { (input_row - 1) as usize } else { 0 };
        let max_scroll = total.saturating_sub(view_h);
        let off = scroll_offset.min(max_scroll);
        // ステータスバークリア
        queue!(stdout, cursor::MoveTo(0,0), Clear(ClearType::CurrentLine)).ok();
        // ステータス文字列組み立て
        let bar_core = format!(" p2witter | スクロール:{}/{} ", off, max_scroll);
        let mut bar = bar_core.clone();
        if !status_msg.is_empty() { bar.push_str(status_msg); }
        if display_width(&bar) > safe_w { bar = truncate_display(&bar, safe_w); }
        queue!(stdout, cursor::MoveTo(0,0)).ok();
        // 反転表示 (端末対応簡易)
        queue!(stdout, style::SetAttribute(style::Attribute::Reverse)).ok();
        let _ = write!(stdout, "{}", bar);
        queue!(stdout, style::SetAttribute(style::Attribute::Reset)).ok();
        // メッセージ領域クリア & 描画 (y=1 .. input_row-1)
        for y in 1..input_row { queue!(stdout, cursor::MoveTo(0,y), Clear(ClearType::CurrentLine)).ok(); }
        let mut start_idx = 0usize; if total > view_h { start_idx = total - view_h - off; }
        for (i, line) in flat_lines.iter().enumerate().skip(start_idx) {
            let y = (i-start_idx) as u16 + 1; if y >= input_row { break; }
            queue!(stdout, cursor::MoveTo(0,y)).ok(); let _ = write!(stdout, "{}", line);
        }
        (w,h)
    }
    fn redraw_input(stdout: &mut io::Stdout, input: &str, cursor_pos: usize) {
        use crossterm::{terminal, queue, cursor};
        use crossterm::terminal::{Clear, ClearType};
    let (w, h) = terminal::size().unwrap_or((80,24)); let y = h.saturating_sub(1);
    let safe_w = w.saturating_sub(1) as usize; // 自動折返し回避
    queue!(stdout, cursor::MoveTo(0,y), Clear(ClearType::CurrentLine)).ok();
    // 入力の表示幅でスクロールしつつ表示（カーソル位置を中心に可視化）
    let max_input_cols = safe_w.saturating_sub(2); // "> " のぶん、末尾1桁は空ける
    let (left, right) = split_at_char(input, cursor_pos);
    let left_w = display_width(&left);
    let shown_input = if left_w <= max_input_cols {
        let rem = max_input_cols - left_w;
        let right_vis = truncate_display(&right, rem);
        format!("{}{}", left, right_vis)
    } else {
        take_last_display(&left, max_input_cols)
    };
    let prompt = format!("> {}", shown_input);
    let _ = write!(stdout, "{}", prompt);
    let caret_cols_in_prompt = if left_w <= max_input_cols { left_w } else { display_width(&shown_input) };
    let caret_cols_total = 2usize + caret_cols_in_prompt;
    let caret_x = if w == 0 { 0 } else { caret_cols_total.min(safe_w) } as u16;
    queue!(stdout, cursor::MoveTo(caret_x, y), cursor::Show).ok();
    }
    fn render(stdout: &mut io::Stdout, messages: &Vec<String>, input: &str, st: &mut DrawState, scroll_offset: usize, status_msg: &str, cursor_pos: usize) {
        let need_full = st.force_full || st.last_msg_len != messages.len();
        if need_full { redraw_full(stdout, messages, scroll_offset, status_msg); st.last_msg_len = messages.len(); st.force_full = false; }
        if need_full || st.last_input_len != input.len() || st.last_cursor_pos != cursor_pos { redraw_input(stdout, input, cursor_pos); st.last_input_len = input.len(); st.last_cursor_pos = cursor_pos; }
        let _ = stdout.flush();
    }
    let mut draw_state = DrawState::new();
    fn push_msg(messages: &mut Vec<String>, st: &mut DrawState, msg: String) { messages.push(msg); st.force_full = true; }
    // デバッグ専用ログ。config の debug=true のときのみ流す
    fn push_debug_msg(messages: &mut Vec<String>, st: &mut DrawState, msg: impl Into<String>) {
        if crate::config::is_debug() {
            push_msg(messages, st, format!("[DEBUG] {}", msg.into()));
        }
    }
    let mut status_msg = if handle.starts_with('@') && handle.chars().count() < 80 {
        "TUI開始。/help でコマンド一覧。/open <port> または /connect <token>。/exit で終了。[F2: 選択/コピーモード切替]".into()
    } else {
        "ハンドル未設定です。/handle @name を先に実行してください".into()
    };

    // スクロールと履歴状態
    let mut scroll_offset: usize = 0; // 0=最新 (一番下)。増えると過去へ。
    let mut history: Vec<String> = Vec::new();
    let mut history_pos: Option<usize> = None; // history 内のインデックス (0..len-1)。None は編集中の新規行。
    // VS Code 統合ターミナルでのマウス選択・コピー用モード
    // F2 でトグル: 有効時は MouseCapture を解除し、画面更新を止めて選択しやすくする
    let mut copy_mode: bool = false;

    // 入力カーソル（文字単位）
    let mut cursor_pos: usize = 0;

    while running {
        // ネットワークからのメッセージ取り込み (先に集めてからイベント / 描画判定)
    while let Ok(m) = rx_from_threads.try_recv() { push_msg(&mut messages, &mut draw_state, m); if scroll_offset == 0 { /* stay bottom */ } }

        // イベント待ち (50ms)
        if event::poll(Duration::from_millis(50)).unwrap_or(false) {
            if let Ok(ev) = event::read() {
                match ev {
                    Event::Key(KeyEvent { code, modifiers, kind, .. }) => {
                        // KeyEventKind を見て Press のみ処理 (Release/Repeat を無視) → 二重入力防止
                        if kind != KeyEventKind::Press { continue; }
                        // 選択/コピーモード中は F2 のみ受け付け、それ以外は UI 操作を抑止
                        if copy_mode {
                            match code {
                                KeyCode::F(2) => {
                                    copy_mode = false;
                                    // マウスキャプチャを再度有効化（失敗時はステータスに表示）
                                    if let Err(e) = execute!(stdout, EnableMouseCapture) {
                                        status_msg = format!("選択/コピーモード終了（MouseCapture再有効化失敗: {e}）");
                                    } else {
                                        status_msg = "選択/コピーモード終了".into();
                                    }
                                    draw_state.force_full = true;
                                    // 復帰時に即再描画
                                    render(&mut stdout, &messages, &input, &mut draw_state, scroll_offset, &status_msg, cursor_pos);
                                }
                                _ => { /* 選択の邪魔をしない */ }
                            }
                            continue;
                        }
                        match code {
                            // F2 で選択/コピーモードに入る
                            KeyCode::F(2) => {
                                // 先に MouseCapture を解除（失敗時はステータスに表示）
                                let mut msg = "選択/コピーモード: マウスで選択し、Ctrl+Shift+C でコピー、F2 で復帰".to_string();
                                if let Err(e) = execute!(stdout, DisableMouseCapture) {
                                    msg = format!("選択/コピーモード: MouseCapture解除失敗: {e}");
                                }
                                status_msg = msg;
                                draw_state.force_full = true;
                                copy_mode = true;
                                // 案内を描画（この直後からはループ末尾の描画は抑止される）
                                render(&mut stdout, &messages, &input, &mut draw_state, scroll_offset, &status_msg, cursor_pos);
                            }
                            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => { running = false; }
                            KeyCode::Char(ch) => {
                                let (mut left, right) = split_at_char(&input, cursor_pos);
                                left.push(ch);
                                input = left + &right;
                                cursor_pos += 1;
                            }
                            KeyCode::Backspace => {
                                if cursor_pos > 0 {
                                    let (left, right) = split_at_char(&input, cursor_pos);
                                    let mut left2 = left;
                                    left2.pop(); // 1 文字削除（pop は UTF-8 末尾 1 文字）
                                    input = left2 + &right;
                                    cursor_pos -= 1;
                                }
                            }
                            KeyCode::Left => {
                                if cursor_pos > 0 { cursor_pos -= 1; }
                            }
                            KeyCode::Right => {
                                let total = input.chars().count();
                                if cursor_pos < total { cursor_pos += 1; }
                            }
                            KeyCode::Enter => {
                                let line = input.trim().to_string();
                                let parts: Vec<String> = line.split_whitespace().map(|s| s.to_string()).collect();
                                // ローカルエコーは行わない (サーバ経由で戻る表示と二重防止)
                                match parts.get(0).map(|s| s.as_str()) {
                                    Some("/help") => {
                                        if parts.len() >= 2 {
                                            let target = &parts[1];
                                            let key = if target.starts_with('/') { target.clone() } else { format!("/{}", target) };
                                            if let Some(spec) = find_command(&key) {
                                                let msg = format!("{}\n  説明: {}\n  使い方: {}", spec.name, spec.description, spec.usage);
                                                push_msg(&mut messages, &mut draw_state, msg);
                                            } else {
                                                status_msg = format!("不明なコマンド: {} (/help で一覧)", key); draw_state.force_full = true;
                                            }
                                        } else {
                                            let mut lines = vec!["コマンド一覧:".to_string()];
                                            for c in COMMANDS.iter() { lines.push(format!("{:10} - {}", c.name, c.description)); }
                                            push_msg(&mut messages, &mut draw_state, lines.join("\n"));
                                        }
                                    }
                                    Some("/open") => {
                                        if let Some(port) = parts.get(1) {
                                            if !(handle.starts_with('@') && handle.chars().count() < 80) { status_msg = "ハンドル未設定です。/handle @name を先に実行してください".into(); draw_state.force_full = true; continue; }
                                            if active_thread_tx.is_none() {
                                                let tx_main = tx_to_main.clone();
                                                let (tx_thread, rx_thread) = mpsc::channel();
                                                let handle = thread::spawn(move || { run_network(tx_main, rx_thread); });
                                                active_thread_tx = Some(tx_thread); active_thread_handle = Some(handle);
                                            }
                                            if let Some(ref tx) = active_thread_tx { tx.send(format!("/open {}", port)).ok(); }
                                        } else { status_msg = "使い方: /open <port>".into(); draw_state.force_full = true; }
                                    }
                                    Some("/connect") => {
                                        if let Some(arg) = parts.get(1) {
                                            if !(handle.starts_with('@') && handle.chars().count() < 80) { status_msg = "ハンドル未設定です。/handle @name を先に実行してください".into(); draw_state.force_full = true; continue; }
                                            if active_thread_tx.is_none() {
                                                let tx_main = tx_to_main.clone();
                                                let (tx_thread, rx_thread) = mpsc::channel();
                                                let handle = thread::spawn(move || { run_network(tx_main, rx_thread); });
                                                active_thread_tx = Some(tx_thread); active_thread_handle = Some(handle);
                                            }
                                            // 入力が平文アドレスなら自動でトークン化して送る
                                            let token = if arg.contains(':') {
                                                match crypto::encrypt_conninfo_to_hex(arg) { Ok(t) => t, Err(_) => arg.clone() }
                                            } else { arg.clone() };
                                            if let Some(ref tx) = active_thread_tx { tx.send(format!("/connect {}", token)).ok(); }
                                        } else { status_msg = "使い方: /connect <token>".into(); draw_state.force_full = true; }
                                    }
                                    Some("/handle") => {
                                        if let Some(name) = parts.get(1) {
                                            let valid = name.starts_with('@') && name.chars().count() < 80;
                                            if valid {
                                                handle = name.clone();
                                                // 保存
                                                let _ = config::upsert_value_and_save("user.handle", toml::Value::String(handle.clone()));
                                                status_msg = format!("ハンドルを {} に設定", handle);
                                                // ネットワークスレッドがあれば伝える
                                                if let Some(ref tx) = active_thread_tx { let _ = tx.send(format!("/handle {}", handle)); }
                                            } else {
                                                status_msg = "使い方: /handle @name （@で開始し80文字未満）".into();
                                            }
                                            draw_state.force_full = true;
                                        } else { status_msg = "使い方: /handle @name".into(); draw_state.force_full = true; }
                                    }
                                    
                                    Some("/exit") => {
                                        status_msg = "終了中...".into(); draw_state.force_full = true;
                                        if let Some(ref tx) = active_thread_tx { tx.send("/exit".into()).ok(); drop(active_thread_tx.take()); }
                                        if let Some(handle) = active_thread_handle.take() { handle.join().ok(); }
                                        running = false;
                                    }
                                    Some("/init") => {
                                        match crypto::generate_ed25519_keypair() {
                                            Ok(k) => {
                                                config::upsert_value_and_save("key.pkcs8", toml::Value::String(crypto::to_hex(&k.pkcs8))).ok();
                                                config::upsert_value_and_save("key.public", toml::Value::String(crypto::to_hex(&k.public))).ok();
                                                status_msg = format!("鍵生成完了 public_len={}", k.public.len()); draw_state.force_full = true;
                                            }
                                            Err(e) => { status_msg = format!("鍵生成失敗: {e}"); draw_state.force_full = true; }
                                        }
                                    }
                                    Some("/peers") => {
                                        if let Some(ref tx) = active_thread_tx { tx.send("/peers".into()).ok(); } else { status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true; }
                                    }
                                    Some("/close") => {
                                        if let Some(ref tx) = active_thread_tx { tx.send("/close".into()).ok(); } else { status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true; }
                                    }
                                    Some("/disconnect") => {
                                        if parts.len() < 2 { status_msg = "使い方: /disconnect <id>".into(); draw_state.force_full = true; }
                                        else if let Some(ref tx) = active_thread_tx { tx.send(format!("/disconnect {}", parts[1])).ok(); } else { status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true; }
                                    }
                                    Some("/dm") => {
                                        if parts.len() < 3 { status_msg = "使い方: /dm <to_id> <message>".into(); draw_state.force_full = true; }
                                        else if let Some(ref tx) = active_thread_tx {
                                            if !(handle.starts_with('@') && handle.chars().count() < 80) { status_msg = "ハンドル未設定です。/handle @name".into(); draw_state.force_full = true; continue; }
                                            let to_id=&parts[1];
                                            let value=parts[2..].join(" ");
                                            // ローカルエコー
                                            push_msg(&mut messages, &mut draw_state, format!("{}: {} ○", handle, value));
                                            tx.send(format!("/dm {} {}", to_id, value)).ok();
                                        } else { status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true; }
                                    }
                                    Some("/certs") => { if let Some(ref tx) = active_thread_tx { tx.send("/certs".into()).ok(); } else { status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true; } }
                                    Some("/cert") => { if parts.len()<2 { status_msg = "使い方: /cert <id>".into(); draw_state.force_full = true; } else if let Some(ref tx)=active_thread_tx { tx.send(format!("/cert {}", parts[1])).ok(); } else { status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true; } }
                                    Some("/msg") => {
                                        if parts.len() < 2 { status_msg = "使い方: /msg <message>".into(); draw_state.force_full = true; }
                                        else if let Some(ref tx) = active_thread_tx {
                                            if !(handle.starts_with('@') && handle.chars().count() < 80) { status_msg = "ハンドル未設定です。/handle @name".into(); draw_state.force_full = true; continue; }
                                            let value=parts[1..].join(" ");
                                            // ローカルエコー
                                            push_msg(&mut messages, &mut draw_state, format!("{}: {} ○", handle, value));
                                            tx.send(format!("/msg {}", value)).ok();
                                        } else {
                                            // ネットワークなしでもローカルエコーは行う
                                            let value=parts[1..].join(" ");
                                            push_msg(&mut messages, &mut draw_state, format!("{}: {} ○", handle, value));
                                            status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true;
                                        }
                                    }
                                    Some(other) => {
                                        if other.starts_with('/') {
                                            let hint = if find_command(other).is_some() { "" } else { " (/help で一覧)" };
                                            status_msg = format!("不明なコマンド: {}{}", other, hint); draw_state.force_full = true;
                                        }
                                        else if let Some(ref tx) = active_thread_tx {
                                            if !(handle.starts_with('@') && handle.chars().count() < 80) { status_msg = "ハンドル未設定です。/handle @name".into(); draw_state.force_full = true; continue; }
                                            // ローカルエコー
                                            push_msg(&mut messages, &mut draw_state, format!("{}: {} ○", handle, line));
                                            tx.send(format!("/msg {}", line)).ok();
                                        } else {
                                            // ネットワークなしでもローカルエコー
                                            push_msg(&mut messages, &mut draw_state, format!("{}: {} ○", handle, line));
                                            status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true;
                                        }
                                    }
                                    None => {}
                                }
                                input.clear(); cursor_pos = 0;
                                if !line.is_empty() { history.push(line); history_pos = None; }
                            }
                            KeyCode::Esc => { input.clear(); cursor_pos = 0; history_pos = None; }
                            KeyCode::Up => {
                                if history.is_empty() { continue; }
                                let new_pos = match history_pos { None => history.len().saturating_sub(1), Some(p) => p.saturating_sub(1) };
                                history_pos = Some(new_pos);
                                input = history[new_pos].clone();
                                cursor_pos = input.chars().count();
                            }
                            KeyCode::Down => {
                                if history.is_empty() { continue; }
                                if let Some(p) = history_pos {
                                    if p + 1 < history.len() { history_pos = Some(p+1); input = history[p+1].clone(); }
                                    else { history_pos = None; input.clear(); }
                                    cursor_pos = input.chars().count();
                                }
                            }
                            KeyCode::Tab => {}
                            _ => {}
                        }
                    }
                    Event::Mouse(me) => {
                        use crossterm::event::MouseEventKind;
                        use crossterm::terminal;
                        // 入力行(最終行)以外でのスクロールのみ反応
                        let (_w, h) = terminal::size().unwrap_or((80,24));
                        let input_row = h.saturating_sub(1); // 入力行
                        if me.row == 0 { /* ステータス行: クリック等は今は無視 */ }
                        if me.row == input_row { continue; }
                        match me.kind {
                            MouseEventKind::ScrollUp => { scroll_offset = scroll_offset.saturating_add(1); draw_state.force_full = true; }
                            MouseEventKind::ScrollDown => { if scroll_offset > 0 { scroll_offset -= 1; draw_state.force_full = true; } }
                            _ => {}
                        }
                    }
                    Event::Resize(_, _) => { /* 再描画は次ループで常に行う */ }
                    _ => {}
                }
            }
        }

        // 選択/コピーモード中は描画更新を止め、選択が崩れないようにする
        if !copy_mode {
            render(&mut stdout, &messages, &input, &mut draw_state, scroll_offset, &status_msg, cursor_pos);
        }
    }

    // クリーンアップ
    execute!(stdout, DisableMouseCapture, LeaveAlternateScreen).ok();
    disable_raw_mode().ok();
    println!("終了しました");
}

fn run_network(tx_main: Sender<String>, rx_thread: Receiver<String>) {
    tx_main.send("ネットワークスレッド開始".to_string()).ok();
    let mut listener: Option<TcpListener> = None;
    let mut clients: Vec<TcpStream> = Vec::new();
    // 各 client ごとのデコーダ
    let mut decoders: Vec<protocol::Decoder> = Vec::new();
    #[derive(Clone, Debug)]
    struct PeerMeta { public_key: Vec<u8>, last_valid: bool, last_timestamp: u64, handle: Option<String> }
    let mut peer_meta: Vec<Option<PeerMeta>> = Vec::new();
    let mut buf = [0u8; 2048];
    // ハンドル（必須）
    let mut handle: String = config::get_value("user.handle")
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();

    // 署名用鍵を読む (存在しなければ None)
    let mut pkcs8: Option<Vec<u8>> = None;
    let mut public: Option<Vec<u8>> = None;
    // 起動時に読み込み ( /init 後は再起動で有効 )。将来ホットリロードするなら /reload 等追加。
    if let (Some(pk_hex), Some(pub_hex)) = (
        config::get_value("key.pkcs8").and_then(|v| v.as_str().map(|s| s.to_string())),
        config::get_value("key.public").and_then(|v| v.as_str().map(|s| s.to_string()))
    ) {
        let pk_bytes = crypto::from_hex(&pk_hex).unwrap_or_default();
        let pub_bytes = crypto::from_hex(&pub_hex).unwrap_or_default();
        if !pk_bytes.is_empty() && !pub_bytes.is_empty() { pkcs8 = Some(pk_bytes); public = Some(pub_bytes); }
    }

    loop {
        // コマンド処理: drain できるだけ読む
        while let Ok(cmd) = rx_thread.try_recv() {
            if cmd == "/exit" { tx_main.send("/exit を受信 -> 終了します".to_string()).ok(); return; }
            if let Some(rest) = cmd.strip_prefix("/open ") {
                if listener.is_some() {
                    tx_main.send("既に待受中（/open は同時に1つまで）".into()).ok();
                } else {
                    match TcpListener::bind(format!("127.0.0.1:{}", rest)) {
                        Ok(l) => { 
                            l.set_nonblocking(true).ok(); 
                            listener = Some(l); 
                            let addr = format!("127.0.0.1:{}", rest);
                            let tok = crypto::encrypt_conninfo_to_hex(&addr).unwrap_or_else(|_| "?".into());
                            tx_main.send(format!("待受開始 (token={})", tok)).ok(); 
                        }
                        Err(e) => { tx_main.send(format!("バインドエラー: {:?}", e)).ok(); }
                    }
                }
            } else if let Some(rest) = cmd.strip_prefix("/connect ") {
                // トークンのみ受け付け。復号失敗ならエラー
                let target = match crypto::decrypt_conninfo_from_hex(rest) { Ok(s) => s, Err(e) => { tx_main.send(format!("接続トークンの復号エラー: {}", e)).ok(); continue; } };
                match TcpStream::connect(&target) {
                    Ok(s) => {
                        let s = s; s.set_nonblocking(true).ok();
                        clients.push(s);
                        decoders.push(protocol::Decoder::new());
                        peer_meta.push(None);
                        let id = clients.len()-1;
                        // 接続直後に公開鍵ハンドシェイクを送信
                        if let (Some(pubk), Some(pk)) = (public.as_ref(), pkcs8.as_ref()) {
                            if let Some(hello) = build_signed_hello(&handle, pk, pubk) {
                                let frame = protocol::encode(&hello);
                                let _ = clients[id].write_all(&frame);
                            }
                        }
                        tx_main.send(format!("接続完了 (token={}) id={}", rest, id)).ok();
                    }
                    Err(e) => { tx_main.send(format!("接続エラー (token={}): {:?}", rest, e)).ok(); }
                }
            } else if cmd == "/close" {
                if listener.is_some() { listener = None; tx_main.send("待受を終了しました".into()).ok(); } else { tx_main.send("待受は起動していません".into()).ok(); }
            } else if let Some(rest) = cmd.strip_prefix("/disconnect ") {
                if let Ok(id) = rest.trim().parse::<usize>() {
                    if id < clients.len() { clients.remove(id); decoders.remove(id); peer_meta.remove(id); tx_main.send(format!("切断しました id {}", id)).ok(); }
                    else { tx_main.send(format!("切断: 不正な id {}", id)).ok(); }
                } else { tx_main.send(format!("切断: 解析エラー '{}': 数値を指定してください", rest)).ok(); }
            } else if cmd == "/peers" {
                let mut lines = Vec::new();
                lines.push(format!("ピア数={} 待受={}", clients.len(), listener.is_some()));
                for (i, c) in clients.iter().enumerate() {
                    let addr = c.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into());
                    let tok = crypto::encrypt_conninfo_to_hex(&addr).unwrap_or_else(|_| "?".into());
                    let fp = peer_meta.get(i).and_then(|m| m.as_ref()).map(|m| {
                        let d = ring::digest::digest(&ring::digest::SHA256, &m.public_key);
                        let h = crypto::to_hex(d.as_ref());
                        format!("指紋={}", &h[..16])
                    }).unwrap_or_else(|| "指紋=?".into());
                    lines.push(format!("id={} token={} {}", i, tok, fp));
                }
                tx_main.send(lines.join("\n")).ok();
            } else if cmd == "/certs" {
                let mut lines = vec!["証明書:".to_string()];
                for (i, meta) in peer_meta.iter().enumerate() {
                    match meta {
                        Some(m) => {
                            let d = ring::digest::digest(&ring::digest::SHA256, &m.public_key);
                            let h = crypto::to_hex(d.as_ref());
                            lines.push(format!("id={} 有効={} ts={} 公開鍵長={} 指紋={}", i, m.last_valid, m.last_timestamp, m.public_key.len(), &h[..32]));
                        }
                        None => lines.push(format!("id={} <鍵なし>", i)),
                    }
                }
                tx_main.send(lines.join("\n")).ok();
            } else if let Some(rest) = cmd.strip_prefix("/cert ") {
                if let Ok(id) = rest.trim().parse::<usize>() {
                    if id < peer_meta.len() {
                        match &peer_meta[id] {
                            Some(m) => {
                                let d = ring::digest::digest(&ring::digest::SHA256, &m.public_key);
                                let h = crypto::to_hex(d.as_ref());
                                tx_main.send(format!("証明書 id={} 有効={} ts={} 公開鍵={} 指紋={}", id, m.last_valid, m.last_timestamp, crypto::to_hex(&m.public_key), h)).ok();
                            }
                            None => { tx_main.send(format!("証明書 id={} まだ鍵がありません", id)).ok(); }
                        }
                    } else { tx_main.send(format!("証明書: 不正な id {}", id)).ok(); }
                } else { tx_main.send(format!("証明書: 解析エラー '{}'", rest)).ok(); }
            } else if let Some(rest) = cmd.strip_prefix("/handle ") {
                let name = rest.trim();
                if name.starts_with('@') && name.chars().count() < 80 {
                    handle = name.to_string();
                    tx_main.send(format!("ハンドル適用: {}", handle)).ok();
                } else {
                    tx_main.send("/handle は @から始まり80文字未満".into()).ok();
                }
            } else if let Some(rest) = cmd.strip_prefix("/msg ") {
                // 送信メッセージをプロトコルフレーム化
                if let (Some(ref pk), Some(ref pubk)) = (pkcs8.as_ref(), public.as_ref()) {
                    // 送信本文にハンドルをプレーンで含める
                    let body = format!("{}: {}", handle, rest);
                    if let Some(m) = build_signed_chat(&body, pk, pubk) {
                        let frame = protocol::encode(&m);
                        let mut remove = Vec::new();
                        for (i, c) in clients.iter_mut().enumerate() {
                            if let Err(e) = c.write_all(&frame) { tx_main.send(format!("送信エラー {}: {:?}", i, e)).ok(); remove.push(i); }
                        }
                        for i in remove.into_iter().rev() { clients.remove(i); decoders.remove(i); }
                    } else { tx_main.send("署名生成失敗".into()).ok(); }
                } else {
                    tx_main.send("鍵未生成 (/init を先に実行)".into()).ok();
                }
            } else if let Some(rest) = cmd.strip_prefix("/dm ") {
                // /dm <to_id> <message>
                let mut iter = rest.splitn(2, ' ');
                let to = iter.next().unwrap_or("");
                let msg_body = iter.next().unwrap_or("");
                if let Ok(target) = to.parse::<usize>() {
                    if target < clients.len() {
                        if let (Some(ref pk), Some(ref pubk)) = (pkcs8.as_ref(), public.as_ref()) {
                            let body = format!("{}: {}", handle, msg_body);
                            if let Some(m) = build_signed_dm(&body, pk, pubk) {
                                let frame = protocol::encode(&m);
                                if let Err(e) = clients[target].write_all(&frame) { tx_main.send(format!("DM送信エラー {}: {:?}", target, e)).ok(); }
                            } else { tx_main.send("DM署名生成失敗".into()).ok(); }
                        } else { tx_main.send("鍵未生成 (/init を先に実行)".into()).ok(); }
                    } else {
                        tx_main.send(format!("DM 宛先 id {} が範囲外です", target)).ok();
                    }
                } else {
                    tx_main.send(format!("不正な DM 宛先: {}", to)).ok();
                }
            }
        }

        // accept
        if let Some(l) = &listener {
            loop {
                match l.accept() {
                    Ok((s, peer)) => {
                        let s = s; s.set_nonblocking(true).ok();
                        clients.push(s);
                        decoders.push(protocol::Decoder::new());
                        peer_meta.push(None);
                        // 受け入れ側も公開鍵を送信
                        let id = clients.len()-1;
                        if let (Some(pubk), Some(pk)) = (public.as_ref(), pkcs8.as_ref()) {
                            if let Some(hello) = build_signed_hello(&handle, pk, pubk) {
                                let frame = protocol::encode(&hello);
                                let _ = clients[id].write_all(&frame);
                            }
                        }
                        let token = crypto::encrypt_conninfo_to_hex(&peer.to_string()).unwrap_or_else(|_| "?".to_string());
                        tx_main.send(format!("接続受入 (token={}) id={}", token, id)).ok();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => { tx_main.send(format!("受け入れエラー: {:?}", e)).ok(); break; }
                }
            }
        }

        // 読み取り (バイナリプロトコル優先)
        let mut received_frames: Vec<(usize, protocol::Message)> = Vec::new();
        let mut remove_indices: Vec<usize> = Vec::new();
        for (idx, c) in clients.iter_mut().enumerate() {
            match c.read(&mut buf) {
                Ok(0) => { tx_main.send(format!("クライアント {} が切断しました", idx)).ok(); remove_indices.push(idx); }
                Ok(n) => { if n>0 { decoders[idx].feed(&buf[..n]); if let Ok(mut msgs) = decoders[idx].drain() { for m in msgs.drain(..) { received_frames.push((idx, m)); } } } }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => { tx_main.send(format!("受信エラー {}: {:?}", idx, e)).ok(); remove_indices.push(idx); }
            }
        }

        // 中継と表示 + 署名検証
        for (src, msg) in received_frames.iter() {
            // テキスト復号/デコード
            let txt = if msg.kind == protocol::MsgKind::DM {
                match crypto::decrypt_dm_payload(&msg.payload) {
                    Ok(p) => String::from_utf8_lossy(&p).to_string(),
                    Err(_) => "<DM復号エラー>".to_string(),
                }
            } else {
                String::from_utf8_lossy(&msg.payload).to_string()
            };
            let mut signed_state = if msg.signature.is_some() { "○" } else { "・" };
            let mut good = true;
            if let (Some(sig), Some(pk)) = (msg.signature.as_ref(), msg.public_key.as_ref()) {
                // 検証 (public_key & signature は署名対象外領域)
                let minimal = protocol::Message { version: msg.version, kind: msg.kind, payload: msg.payload.clone(), timestamp: msg.timestamp, public_key: None, signature: None };
                let data = protocol::signing_bytes(&minimal);
                if crypto::verify_ed25519(&data, sig, pk).is_err() { signed_state = "×"; good = false; }
                // メタ更新（既存のハンドル情報は維持）
                if *src < peer_meta.len() {
                    let existing_handle = peer_meta[*src].as_ref().and_then(|m| m.handle.clone());
                    peer_meta[*src] = Some(PeerMeta { public_key: pk.clone(), last_valid: good, last_timestamp: msg.timestamp, handle: existing_handle });
                }
            }
            if msg.kind == protocol::MsgKind::DISCONNECT {
                let reason = protocol::disconnect_reason_id(msg).unwrap_or(0);
                tx_main.send(format!("相手から切断通知 id={} reason={}", src, reason)).ok();
                remove_indices.push(*src);
            } else if msg.kind == protocol::MsgKind::HELLO {
                // 相手の公開鍵が含まれていれば保存
                if let Some(pk) = msg.public_key.as_ref() {
                    // HELLO 自体の署名検証
                    let minimal = protocol::Message { version: msg.version, kind: msg.kind, payload: msg.payload.clone(), timestamp: msg.timestamp, public_key: None, signature: None };
                    let data = protocol::signing_bytes(&minimal);
                    if let Some(sig) = msg.signature.as_ref() {
                        if crypto::verify_ed25519(&data, sig, pk).is_err() {
                            // 理由ID=3: HELLO署名不正
                            let disc = protocol::Message::disconnect(current_unix_millis(), 3);
                            let frame = protocol::encode(&disc);
                            let _ = clients[*src].write_all(&frame);
                            tx_main.send(format!("不正HELLO署名: id={} 切断", src)).ok();
                            remove_indices.push(*src);
                            continue;
                        }
                    } else {
                        // 署名なし HELLO は不許可
                        let disc = protocol::Message::disconnect(current_unix_millis(), 3);
                        let frame = protocol::encode(&disc);
                        let _ = clients[*src].write_all(&frame);
                        tx_main.send(format!("HELLO署名なし: id={} 切断", src)).ok();
                        remove_indices.push(*src);
                        continue;
                    }

                    if *src < peer_meta.len() {
                        let peer_handle = String::from_utf8_lossy(&msg.payload).to_string();
                        let valid_handle = peer_handle.starts_with('@') && peer_handle.chars().count() < 80;
                        if !valid_handle {
                            let disc = protocol::Message::disconnect(current_unix_millis(), 2);
                            let frame = protocol::encode(&disc);
                            let _ = clients[*src].write_all(&frame);
                            tx_main.send(format!("不正HELLO: id={} のハンドル '{}' が不正のため切断", src, peer_handle)).ok();
                            remove_indices.push(*src);
                        } else {
                            let meta = PeerMeta { public_key: pk.clone(), last_valid: true, last_timestamp: msg.timestamp, handle: Some(peer_handle) };
                            peer_meta[*src] = Some(meta);
                        }
                    }
                    let d = ring::digest::digest(&ring::digest::SHA256, pk);
                    let h = crypto::to_hex(d.as_ref());
                    tx_main.send(format!("HELLO 受信: id={} 指紋={}", src, &h[..16])).ok();
                } else {
                    tx_main.send(format!("HELLO 受信: id={} (公開鍵なし)", src)).ok();
                }
            } else if msg.kind == protocol::MsgKind::DM {
                // 受信表示: 本文 + 署名状態記号
                let disp = format!("{} {}", txt, signed_state);
                tx_main.send(disp).ok();
            } else {
                // 受信表示: 統一フォーマット（本文に '@handle: ' が含まれている想定）。
                // 署名状態は末尾に半角スペース+記号を付ける。
                let disp = if let Some(Some(meta)) = peer_meta.get(*src).cloned() {
                    if meta.handle.is_some() { format!("{} {}", txt, signed_state) } else if txt.contains(':') { format!("{} {}", txt, signed_state) } else { format!("@{}: {} {}", src, txt, signed_state) }
                } else if txt.contains(':') { format!("{} {}", txt, signed_state) } else { format!("@{}: {} {}", src, txt, signed_state) };
                tx_main.send(disp).ok();
                let frame = protocol::encode(msg);
                for (idx, c) in clients.iter_mut().enumerate() {
                    if idx == *src { continue; }
                    if let Err(e) = c.write_all(&frame) { tx_main.send(format!("Relay write error to {}: {:?}", idx, e)).ok(); remove_indices.push(idx); }
                }
            }

            // 不正検知: ハンドル長チェック（"@...: " のプレフィクスを解析）
            if let Some(colon) = txt.find(':') {
                let name = &txt[..colon].trim();
                if name.starts_with('@') {
                    let count = name.chars().count();
                    if count >= 80 {
                        // 切断: 理由ID=1（ハンドル長超過）
                        let reason_id: u32 = 1;
                        if *src < clients.len() {
                            let disc = protocol::Message::disconnect(current_unix_millis(), reason_id);
                            let frame = protocol::encode(&disc);
                            let _ = clients[*src].write_all(&frame);
                        }
                        tx_main.send(format!("不正検知: id={} のハンドル長({})が制限超過のため切断", src, count)).ok();
                        remove_indices.push(*src);
                        // 次のメッセージ処理へ
                        continue;
                    }
                }
            }
        }

        // 削除
        remove_indices.sort_unstable(); remove_indices.dedup();
    for i in remove_indices.into_iter().rev() { clients.remove(i); decoders.remove(i); peer_meta.remove(i); }

        thread::sleep(Duration::from_millis(15));
    }
}
