use std::io::{self, Write};
use std::sync::mpsc::{self, Sender, Receiver};
use std::thread::{self};
use std::time::Duration;
mod protocol;
mod config;
mod crypto;
mod storage;
mod network_handler;
mod rpc;

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
    let (tx_to_main, rx_from_threads): (Sender<String>, Receiver<String>) = mpsc::channel();
    let mut active_thread_tx: Option<Sender<rpc::Command>> = None;
    let mut active_thread_handle: Option<thread::JoinHandle<()>> = None;
    if let Err(e) = config::init_config_path("./config.toml") { eprintln!("設定初期化に失敗: {e}"); }
    // ストレージ初期化（sled）
    let _ = storage::init_storage("./p2witter.db");

    // TUI 状態
    let mut messages: Vec<String> = Vec::new();
    let mut past_messages: Vec<String> = Vec::new();
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
    fn redraw_full(stdout: &mut io::Stdout, messages: &Vec<String>, scroll_offset: usize, status_msg: &str, past_mode: bool, date_range: &str) -> (u16,u16) {
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
        let bar_core = if past_mode {
        let range = if date_range.is_empty() { "過去ログ".into() } else { date_range.to_string() };
        format!(" p2witter | {} (scroll {} / {}) ", range, off, max_scroll)
    } else {
        format!(" p2witter | スクロール:{}/{} ", off, max_scroll)
    };
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
    fn render(stdout: &mut io::Stdout, messages: &Vec<String>, input: &str, st: &mut DrawState, scroll_offset: usize, status_msg: &str, cursor_pos: usize, past_mode: bool, date_range: &str) {
        let need_full = st.force_full || st.last_msg_len != messages.len();
        if need_full { redraw_full(stdout, messages, scroll_offset, status_msg, past_mode, date_range); st.last_msg_len = messages.len(); st.force_full = false; }
        if need_full || st.last_input_len != input.len() || st.last_cursor_pos != cursor_pos { redraw_input(stdout, input, cursor_pos); st.last_input_len = input.len(); st.last_cursor_pos = cursor_pos; }
        let _ = stdout.flush();
    }
    let mut draw_state = DrawState::new();
    // 画面への追加のみ（保存しない）
    fn push_msg(messages: &mut Vec<String>, st: &mut DrawState, msg: String) { 
        messages.push(msg); 
        st.force_full = true; 
    }
    // ユーザー投稿のみ保存するための専用関数
    fn push_user_msg(messages: &mut Vec<String>, st: &mut DrawState, msg: String) {
        let now = crate::current_unix_millis();
        storage::append_message(now, &msg);
        messages.push(msg);
        st.force_full = true;
    }
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
    // 過去ログモード関連
    let mut past_mode: bool = false; // 過去ログモード
    let mut past_dates: Vec<String> = Vec::new();
    let mut past_date_range: String = String::new();
    let mut past_earliest_idx: Option<usize> = None; // 読み込み済みで最も古い day の past_dates index

    // スクロールと履歴状態
    let mut scroll_offset: usize = 0; // 0=最新 (一番下)。増えると過去へ。
    let mut past_scroll_offset: usize = 0; // 過去ログ用の独立オフセット
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
                                    let view: &Vec<String> = if past_mode { &past_messages } else { &messages };
                                    let off = if past_mode { past_scroll_offset } else { scroll_offset };
                                    render(&mut stdout, view, &input, &mut draw_state, off, &status_msg, cursor_pos, past_mode, &past_date_range);
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
                                let view: &Vec<String> = if past_mode { &past_messages } else { &messages };
                                let off = if past_mode { past_scroll_offset } else { scroll_offset };
                                render(&mut stdout, view, &input, &mut draw_state, off, &status_msg, cursor_pos, past_mode, &past_date_range);
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
                                if cursor_pos > 0 {
                                    if modifiers.contains(KeyModifiers::CONTROL) {
                                        // 単語単位で左へ
                                        let mut new_pos = cursor_pos;
                                        let chars: Vec<char> = input.chars().collect();
                                        // 直前が空白ならスキップ
                                        while new_pos > 0 && (chars[new_pos-1].is_whitespace() || chars[new_pos-1] == '=') { new_pos -= 1; }
                                        // 単語の先頭まで移動
                                        while new_pos > 0 && (!chars[new_pos-1].is_whitespace() || chars[new_pos-1] == '=') { new_pos -= 1; }
                                        cursor_pos = new_pos;
                                    } else {
                                        cursor_pos -= 1;
                                    }
                                }
                            }
                            KeyCode::Right => {
                                if cursor_pos < input.chars().count() {
                                    if modifiers.contains(KeyModifiers::CONTROL) {
                                        // 単語単位で右へ
                                        let mut new_pos = cursor_pos;
                                        let chars: Vec<char> = input.chars().collect();
                                        // 直後が空白ならスキップ
                                        while new_pos < chars.len() && (chars[new_pos].is_whitespace() || chars[new_pos] == '=') { new_pos += 1; }
                                        // 単語の末尾まで移動
                                        while new_pos < chars.len() && (!chars[new_pos].is_whitespace() || chars[new_pos] == '=') { new_pos += 1; }
                                        cursor_pos = new_pos;
                                    } else {
                                        cursor_pos += 1;
                                    }
                                }
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
                                            for c in COMMANDS.iter() { 
                                                if c.name == "/past" {
                                                    lines.push(format!("{:10} - {}", c.name, "過去ログモードのON/OFFを切替。ONで最新日を読み込み。スクロール最上端到達で前日追加ロード"));
                                                } else {
                                                    lines.push(format!("{:10} - {}", c.name, c.description));
                                                }
                                            }
                                            push_msg(&mut messages, &mut draw_state, lines.join("\n"));
                                        }
                                    }
                                    Some("/open") => {
                                        if let Some(port) = parts.get(1) {
                                            if !(handle.starts_with('@') && handle.chars().count() < 80) { status_msg = "ハンドル未設定です。/handle @name を先に実行してください".into(); draw_state.force_full = true; continue; }
                                            if active_thread_tx.is_none() {
                                                let tx_main = tx_to_main.clone();
                                                let (tx_thread, rx_thread) = mpsc::channel();
                                                let handle = thread::spawn(move || { network_handler::network_handler(tx_main, rx_thread); });
                                                active_thread_tx = Some(tx_thread); active_thread_handle = Some(handle);
                                            }
                                            if let Some(ref tx) = active_thread_tx { tx.send(rpc::Command::Open(port.clone())).ok(); }
                                        } else { status_msg = "使い方: /open <port>".into(); draw_state.force_full = true; }
                                    }
                                    Some("/connect") => {
                                        if let Some(arg) = parts.get(1) {
                                            if !(handle.starts_with('@') && handle.chars().count() < 80) { status_msg = "ハンドル未設定です。/handle @name を先に実行してください".into(); draw_state.force_full = true; continue; }
                                            if active_thread_tx.is_none() {
                                                let tx_main = tx_to_main.clone();
                                                let (tx_thread, rx_thread) = mpsc::channel();
                                                let handle = thread::spawn(move || { network_handler::network_handler(tx_main, rx_thread); });
                                                active_thread_tx = Some(tx_thread); active_thread_handle = Some(handle);
                                            }
                                            // 入力が平文アドレスなら自動でトークン化して送る
                                            let token = if arg.contains(':') {
                                                match crypto::encrypt_conninfo_to_hex(arg) { Ok(t) => t, Err(_) => arg.clone() }
                                            } else { arg.clone() };
                                            if let Some(ref tx) = active_thread_tx { tx.send(rpc::Command::Connect(token)).ok(); }
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
                                                if let Some(ref tx) = active_thread_tx { let _ = tx.send(rpc::Command::Handle(handle.clone())); }
                                            } else {
                                                status_msg = "使い方: /handle @name （@で開始し80文字未満）".into();
                                            }
                                            draw_state.force_full = true;
                                        } else { status_msg = "使い方: /handle @name".into(); draw_state.force_full = true; }
                                    }
                                    
                                    Some("/past") => {
                                        if past_mode {
                                            // モード OFF
                                            past_mode = false;
                                            status_msg = "過去ログモード終了".into();
                                            draw_state.force_full = true;
                                            // スクロールは通常表示側を採用
                                            // 過去ログ側は保持
                                        } else {
                                        past_mode = true; // モード ON
                                        past_dates = storage::list_dates();
                                        past_dates.sort();
                                        // 最新日付のみロードし、date_range を設定
                                        if let Some(last_idx) = past_dates.len().checked_sub(1) {
                                            let day = &past_dates[last_idx];
                                            // 構造化読み込みに切替
                                            let recs = storage::load_structured_day(day);
                                            past_messages.clear();
                                            past_scroll_offset = 0;
                                            for r in recs {
                                                // 表示用フォーマット: 可能ならハンドル、なければ from_peer_id で擬似表記
                                                let line = if r.handle.is_some() {
                                                    format!("{} {}", r.text, if r.signed_ok == Some(true) { "○" } else { "・" })
                                                } else if let Some(pid) = r.from_peer_id {
                                                    format!("@{}: {} {}", pid, r.text, if r.signed_ok == Some(true) { "○" } else { "・" })
                                                } else {
                                                    r.text
                                                };
                                                past_messages.push(line);
                                            }
                                            past_date_range = format!("{}~{}", day, day);
                                            past_earliest_idx = Some(last_idx);
                                            status_msg = format!("過去ログモード {}", past_date_range);
                                        } else {
                                            status_msg = "過去ログなし".into();
                                        }
                                        draw_state.force_full = true;
                                        }
                                    }
                                    Some("/exit") => {
                                        status_msg = "終了中...".into(); draw_state.force_full = true;
                                        if let Some(ref tx) = active_thread_tx { tx.send(rpc::Command::Shutdown).ok(); drop(active_thread_tx.take()); }
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
                                        if let Some(ref tx) = active_thread_tx { tx.send(rpc::Command::PeerList).ok(); } else { status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true; }
                                    }
                                    Some("/close") => {
                                        if let Some(ref tx) = active_thread_tx { tx.send(rpc::Command::Close).ok(); } else { status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true; }
                                    }
                                    Some("/disconnect") => {
                                        if parts.len() < 2 { status_msg = "使い方: /disconnect <id>".into(); draw_state.force_full = true; }
                                        else if let Some(ref tx) = active_thread_tx { tx.send(rpc::Command::Disconnect(parts[1].clone())).ok(); } else { status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true; }
                                    }
                                    Some("/dm") => {
                                        if parts.len() < 3 { status_msg = "使い方: /dm <to_id> <message>".into(); draw_state.force_full = true; }
                                        else if let Some(ref tx) = active_thread_tx {
                                            if !(handle.starts_with('@') && handle.chars().count() < 80) { status_msg = "ハンドル未設定です。/handle @name".into(); draw_state.force_full = true; continue; }
                                            let to_id=&parts[1];
                                            let value=parts[2..].join(" ");
                                            // ローカルエコー（ユーザー投稿は保存）
                                            push_user_msg(&mut messages, &mut draw_state, format!("{}: {} ○", handle, value));
                                            tx.send(rpc::Command::DM(to_id.clone(), value)).ok();
                                        } else { status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true; }
                                    }
                                    Some("/certs") => { if let Some(ref tx) = active_thread_tx { tx.send(rpc::Command::Certs).ok(); } else { status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true; } }
                                    Some("/cert") => { if parts.len()<2 { status_msg = "使い方: /cert <id>".into(); draw_state.force_full = true; } else if let Some(ref tx)=active_thread_tx { tx.send(rpc::Command::Disconnect(parts[1].clone())).ok(); } else { status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true; } }
                                    Some("/msg") => {
                                        if parts.len() < 2 { status_msg = "使い方: /msg <message>".into(); draw_state.force_full = true; }
                                        else if let Some(ref tx) = active_thread_tx {
                                            if !(handle.starts_with('@') && handle.chars().count() < 80) { status_msg = "ハンドル未設定です。/handle @name".into(); draw_state.force_full = true; continue; }
                                            let value=parts[1..].join(" ");
                                            // ローカルエコー（ユーザー投稿は保存）
                                            push_user_msg(&mut messages, &mut draw_state, format!("{}: {} ○", handle, value));
                                            tx.send(rpc::Command::Chat(value)).ok();
                                        } else {
                                            // ネットワークなしでもローカルエコーは行う
                                            let value=parts[1..].join(" ");
                                            push_user_msg(&mut messages, &mut draw_state, format!("{}: {} ○", handle, value));
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
                                            // ローカルエコー（ユーザー投稿は保存）
                                            push_user_msg(&mut messages, &mut draw_state, format!("{}: {} ○", handle, line));
                                            tx.send(rpc::Command::Chat(line.clone())).ok();
                                        } else {
                                            // ネットワークなしでもローカルエコー
                                            push_user_msg(&mut messages, &mut draw_state, format!("{}: {} ○", handle, line));
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
                            MouseEventKind::ScrollUp => {
                                if past_mode { past_scroll_offset = past_scroll_offset.saturating_add(1); } else { scroll_offset = scroll_offset.saturating_add(1); }
                                // 過去ログモードで最上端に到達したら前日を追加ロード
                                if past_mode {
                                    use crossterm::terminal;
                                    if let (Some(earliest_idx), true) = (past_earliest_idx, true) {
                                        if earliest_idx > 0 {
                                            // 現在の最大スクロール量を概算: 行折返し考慮せず改行分割のみ
                                            let (_w, h) = terminal::size().unwrap_or((80,24));
                                            let view_h = h.saturating_sub(2) as usize; // (入力行 + ステータス行を除く)
                                            let flat_len: usize = past_messages.iter().map(|m| m.split('\n').count()).sum();
                                            let max_scroll = flat_len.saturating_sub(view_h);
                                            if past_scroll_offset >= max_scroll { // 最上端にいる
                                                let load_idx = earliest_idx - 1;
                                                let day = &past_dates[load_idx];
                                                let recs = storage::load_structured_day(day);
                                                // 先頭に古い日を挿入（古→新）
                                                let mut day_lines: Vec<String> = Vec::new();
                                                for r in recs {
                                                    let line = if r.handle.is_some() {
                                                        format!("{} {}", r.text, if r.signed_ok == Some(true) { "○" } else { "・" })
                                                    } else if let Some(pid) = r.from_peer_id {
                                                        format!("@{}: {} {}", pid, r.text, if r.signed_ok == Some(true) { "○" } else { "・" })
                                                    } else { r.text };
                                                    day_lines.push(line);
                                                }
                                                let inserted = day_lines.len();
                                                if inserted > 0 {
                                                    // 先頭に挿入
                                                    past_messages.splice(0..0, day_lines.into_iter());
                                                    // 視点保持のため scroll_offset を行数ぶん加算
                                                    past_scroll_offset = past_scroll_offset.saturating_add(inserted);
                                                    past_earliest_idx = Some(load_idx);
                                                    // 日付レンジ更新（開始日を差し替え）
                                                    if let Some(pos) = past_date_range.find('~') {
                                                        let end_part = past_date_range[pos+1..].to_string();
                                                        past_date_range = format!("{}~{}", day, end_part);
                                                    }
                                                    status_msg = format!("過去ログ拡張 {}", past_date_range);
                                                }
                                            }
                                        }
                                    }
                                }
                                draw_state.force_full = true;
                            }
                            MouseEventKind::ScrollDown => { 
                                if past_mode { if past_scroll_offset > 0 { past_scroll_offset -= 1; draw_state.force_full = true; } }
                                else { if scroll_offset > 0 { scroll_offset -= 1; draw_state.force_full = true; } }
                            }
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
            let view: &Vec<String> = if past_mode { &past_messages } else { &messages };
            let off = if past_mode { past_scroll_offset } else { scroll_offset };
            render(&mut stdout, view, &input, &mut draw_state, off, &status_msg, cursor_pos, past_mode, &past_date_range);
        }
    }

    // クリーンアップ
    execute!(stdout, DisableMouseCapture, LeaveAlternateScreen).ok();
    disable_raw_mode().ok();
    println!("終了しました");
}