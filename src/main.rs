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
    let mut m = protocol::Message::dm(text, current_unix_millis());
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

    use crossterm::{execute, event};
    use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode};
    use crossterm::event::{Event, KeyCode, KeyModifiers, KeyEvent, KeyEventKind, EnableMouseCapture, DisableMouseCapture};

    enable_raw_mode().expect("raw mode に移行できません");
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).ok();
    // 差分描画用状態と関数 + スクロール/履歴状態 + ステータスバー
    struct DrawState { last_msg_len: usize, last_input_len: usize, force_full: bool }
    impl DrawState { fn new() -> Self { Self { last_msg_len: 0, last_input_len: 0, force_full: true } } }
    fn redraw_full(stdout: &mut io::Stdout, messages: &Vec<String>, scroll_offset: usize, status_msg: &str) -> (u16,u16) {
        use crossterm::{terminal, queue, cursor};
        use crossterm::terminal::{Clear, ClearType};
    use crossterm::style::{self};
        let (w, h) = terminal::size().unwrap_or((80,24));
        let input_row = h.saturating_sub(1); // 最下行
        let msg_area_rows = if h >= 2 { (h - 2) as usize } else { 0 }; // 上1行ステータス, 下1行入力
        // スクロールオフセット: 0 が最新。offset が増えると過去方向
        let total = messages.len();
        let view_h = msg_area_rows;
        let max_scroll = total.saturating_sub(view_h);
        let off = scroll_offset.min(max_scroll);
        let mut start = 0usize; if total > view_h { start = total - view_h - off; }
        // 画面全消去は避けステータス+メッセージ領域のみクリア
        queue!(stdout, cursor::Hide).ok();
        // ステータスバークリア
        queue!(stdout, cursor::MoveTo(0,0), Clear(ClearType::CurrentLine)).ok();
        // ステータス文字列組み立て
    let bar_core = format!(" p2witter | スクロール:{}/{} ", off, max_scroll);
        let mut bar = bar_core.clone();
    if !status_msg.is_empty() { bar.push_str(status_msg); }
    if display_width(&bar) > w as usize { bar = truncate_display(&bar, w as usize); }
        queue!(stdout, cursor::MoveTo(0,0)).ok();
        // 反転表示 (端末対応簡易)
        queue!(stdout, style::SetAttribute(style::Attribute::Reverse)).ok();
        let _ = write!(stdout, "{:<width$}", bar, width = w as usize);
        queue!(stdout, style::SetAttribute(style::Attribute::Reset)).ok();
        // メッセージ領域クリア & 描画 (y=1 .. input_row-1)
        for y in 1..input_row { queue!(stdout, cursor::MoveTo(0,y), Clear(ClearType::CurrentLine)).ok(); }
        for (i, msg) in messages.iter().enumerate().skip(start) {
            let y = (i-start) as u16 + 1; if y >= input_row { break; }
            let mut line = msg.replace('\n', "\\n"); if display_width(&line) > w as usize { line = truncate_display(&line, w as usize); }
            queue!(stdout, cursor::MoveTo(0,y)).ok(); let _ = write!(stdout, "{}", line);
        }
        (w,h)
    }
    fn redraw_input(stdout: &mut io::Stdout, input: &str, cursor_pos: usize) {
        use crossterm::{terminal, queue, cursor};
        use crossterm::terminal::{Clear, ClearType};
    let (w, h) = terminal::size().unwrap_or((80,24)); let y = h.saturating_sub(1);
    queue!(stdout, cursor::MoveTo(0,y), Clear(ClearType::CurrentLine)).ok();
    // 入力の表示幅でスクロールしつつ表示（カーソル位置を中心に可視化）
    let max_input_cols = w.saturating_sub(2) as usize; // "> " のぶん
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
    let _ = write!(stdout, "{:<width$}", prompt, width = w as usize);
    let caret_cols_in_prompt = if left_w <= max_input_cols { left_w } else { display_width(&shown_input) };
    let caret_cols_total = 2usize + caret_cols_in_prompt;
    let caret_x = if w == 0 { 0 } else { caret_cols_total.min((w - 1) as usize) } as u16;
    queue!(stdout, cursor::MoveTo(caret_x, y), cursor::Show).ok();
    }
    fn render(stdout: &mut io::Stdout, messages: &Vec<String>, input: &str, st: &mut DrawState, scroll_offset: usize, status_msg: &str, cursor_pos: usize) {
        let need_full = st.force_full || st.last_msg_len != messages.len();
        if need_full { redraw_full(stdout, messages, scroll_offset, status_msg); st.last_msg_len = messages.len(); st.force_full = false; }
        if need_full || st.last_input_len != input.len() { redraw_input(stdout, input, cursor_pos); st.last_input_len = input.len(); }
        let _ = stdout.flush();
    }
    let mut draw_state = DrawState::new();
    fn push_msg(messages: &mut Vec<String>, st: &mut DrawState, msg: String) { messages.push(msg); st.force_full = true; }
    let mut status_msg = String::from("TUI開始。/open <port> または /connect <token>。/exit で終了。[F2: 選択/コピーモード切替]");

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
                                redraw_input(&mut stdout, &input, cursor_pos);
                            }
                            KeyCode::Backspace => {
                                if cursor_pos > 0 {
                                    let (left, right) = split_at_char(&input, cursor_pos);
                                    let mut left2 = left;
                                    left2.pop(); // 1 文字削除（pop は UTF-8 末尾 1 文字）
                                    input = left2 + &right;
                                    cursor_pos -= 1;
                                    redraw_input(&mut stdout, &input, cursor_pos);
                                }
                            }
                            KeyCode::Left => {
                                if cursor_pos > 0 { cursor_pos -= 1; }
                                redraw_input(&mut stdout, &input, cursor_pos);
                            }
                            KeyCode::Right => {
                                let total = input.chars().count();
                                if cursor_pos < total { cursor_pos += 1; }
                                redraw_input(&mut stdout, &input, cursor_pos);
                            }
                            KeyCode::Enter => {
                                let line = input.trim().to_string();
                                let parts: Vec<String> = line.split_whitespace().map(|s| s.to_string()).collect();
                                // ローカルエコーは行わない (サーバ経由で戻る表示と二重防止)
                                match parts.get(0).map(|s| s.as_str()) {
                                    Some("/open") => {
                                        if let Some(port) = parts.get(1) {
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
                                        else if let Some(ref tx) = active_thread_tx { let to_id=&parts[1]; let value=parts[2..].join(" "); tx.send(format!("/dm {} {}", to_id, value)).ok(); } else { status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true; }
                                    }
                                    Some("/certs") => { if let Some(ref tx) = active_thread_tx { tx.send("/certs".into()).ok(); } else { status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true; } }
                                    Some("/cert") => { if parts.len()<2 { status_msg = "使い方: /cert <id>".into(); draw_state.force_full = true; } else if let Some(ref tx)=active_thread_tx { tx.send(format!("/cert {}", parts[1])).ok(); } else { status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true; } }
                                    Some(other) => {
                                        if other.starts_with('/') { status_msg = format!("不明なコマンド: {}", other); draw_state.force_full = true; }
                                        else if let Some(ref tx) = active_thread_tx { tx.send(format!("/msg {}", line)).ok(); } else { status_msg = "ネットワークスレッドがありません。".into(); draw_state.force_full = true; }
                                    }
                                    None => {}
                                }
                                input.clear(); cursor_pos = 0; redraw_input(&mut stdout, &input, cursor_pos);
                                if !line.is_empty() { history.push(line); history_pos = None; }
                            }
                            KeyCode::Esc => { input.clear(); cursor_pos = 0; redraw_input(&mut stdout, &input, cursor_pos); history_pos = None; }
                            KeyCode::Up => {
                                if history.is_empty() { continue; }
                                let new_pos = match history_pos { None => history.len().saturating_sub(1), Some(p) => p.saturating_sub(1) };
                                history_pos = Some(new_pos);
                                input = history[new_pos].clone();
                                cursor_pos = input.chars().count();
                                redraw_input(&mut stdout, &input, cursor_pos);
                            }
                            KeyCode::Down => {
                                if history.is_empty() { continue; }
                                if let Some(p) = history_pos {
                                    if p + 1 < history.len() { history_pos = Some(p+1); input = history[p+1].clone(); }
                                    else { history_pos = None; input.clear(); }
                                    cursor_pos = input.chars().count();
                                    redraw_input(&mut stdout, &input, cursor_pos);
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
    struct PeerMeta { public_key: Vec<u8>, last_valid: bool, last_timestamp: u64 }
    let mut peer_meta: Vec<Option<PeerMeta>> = Vec::new();
    let mut buf = [0u8; 2048];

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
                    Ok(s) => { let s=s; s.set_nonblocking(true).ok(); clients.push(s); decoders.push(protocol::Decoder::new()); peer_meta.push(None); tx_main.send(format!("接続完了 (token={}) id={}", rest, clients.len()-1)).ok(); }
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
            } else if let Some(rest) = cmd.strip_prefix("/msg ") {
                // 送信メッセージをプロトコルフレーム化
                if let (Some(ref pk), Some(ref pubk)) = (pkcs8.as_ref(), public.as_ref()) {
                    if let Some(m) = build_signed_chat(rest, pk, pubk) {
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
                            if let Some(m) = build_signed_dm(msg_body, pk, pubk) {
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
            } else if !cmd.is_empty() {
                // 旧テキスト互換は廃止: 非コマンド入力は /msg 側で処理される
            }
        }

        // accept
        if let Some(l) = &listener {
            loop {
                match l.accept() {
                    Ok((s, peer)) => { let s=s; s.set_nonblocking(true).ok(); clients.push(s); decoders.push(protocol::Decoder::new()); peer_meta.push(None); let token = crypto::encrypt_conninfo_to_hex(&peer.to_string()).unwrap_or_else(|_| "?".to_string()); tx_main.send(format!("接続受入 (token={}) id={}", token, clients.len()-1)).ok(); }
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
            let txt = String::from_utf8_lossy(&msg.payload);
            let mut signed_state = if msg.signature.is_some() { "署名あり" } else { "平文" };
            let mut good = true;
            if let (Some(sig), Some(pk)) = (msg.signature.as_ref(), msg.public_key.as_ref()) {
                // 検証 (public_key & signature は署名対象外領域)
                let minimal = protocol::Message { version: msg.version, kind: msg.kind, payload: msg.payload.clone(), timestamp: msg.timestamp, public_key: None, signature: None };
                let data = protocol::signing_bytes(&minimal);
                if crypto::verify_ed25519(&data, sig, pk).is_err() { signed_state = "署名不正"; good = false; }
                // メタ更新
                if *src < peer_meta.len() { peer_meta[*src] = Some(PeerMeta { public_key: pk.clone(), last_valid: good, last_timestamp: msg.timestamp }); }
            }
            if msg.kind == protocol::MsgKind::DM {
                tx_main.send(format!("DM!! 送信元:{} {} [{}]", src, txt, signed_state)).ok();
            } else {
                tx_main.send(format!("受信(id={}): {} [{}]", src, txt, signed_state)).ok();
                let frame = protocol::encode(msg);
                for (idx, c) in clients.iter_mut().enumerate() {
                    if idx == *src { continue; }
                    if let Err(e) = c.write_all(&frame) { tx_main.send(format!("Relay write error to {}: {:?}", idx, e)).ok(); remove_indices.push(idx); }
                }
            }
        }

        // 削除
        remove_indices.sort_unstable(); remove_indices.dedup();
    for i in remove_indices.into_iter().rev() { clients.remove(i); decoders.remove(i); peer_meta.remove(i); }

        thread::sleep(Duration::from_millis(15));
    }
}
