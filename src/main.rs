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
    if let Err(e) = config::init_config_path("./config.toml") { eprintln!("Failed to init config: {e}"); }

    // TUI 状態
    let mut messages: Vec<String> = Vec::new();
    let mut input = String::new();
    let mut running = true;

    use crossterm::{execute, event};
    use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode};
    use crossterm::event::{Event, KeyCode, KeyModifiers, KeyEvent, KeyEventKind, EnableMouseCapture, DisableMouseCapture};

    enable_raw_mode().expect("raw mode");
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
        let bar_core = format!(" p2witter | scroll:{}/{} ", off, max_scroll);
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
    fn redraw_input(stdout: &mut io::Stdout, input: &str) {
        use crossterm::{terminal, queue, cursor};
        use crossterm::terminal::{Clear, ClearType};
    let (w, h) = terminal::size().unwrap_or((80,24)); let y = h.saturating_sub(1);
    queue!(stdout, cursor::MoveTo(0,y), Clear(ClearType::CurrentLine)).ok();
    // 入力の表示幅で切り詰め
    let max_input_cols = w.saturating_sub(2) as usize; // "> " のぶん
    let shown_input = truncate_display(input, max_input_cols);
    let prompt = format!("> {}", shown_input);
    let _ = write!(stdout, "{:<width$}", prompt, width = w as usize);
    let caret_cols = 2usize + display_width(&shown_input);
    let caret_x = if w == 0 { 0 } else { caret_cols.min((w - 1) as usize) } as u16;
    queue!(stdout, cursor::MoveTo(caret_x, y), cursor::Show).ok();
    }
    fn render(stdout: &mut io::Stdout, messages: &Vec<String>, input: &str, st: &mut DrawState, scroll_offset: usize, status_msg: &str) {
        let need_full = st.force_full || st.last_msg_len != messages.len();
        if need_full { redraw_full(stdout, messages, scroll_offset, status_msg); st.last_msg_len = messages.len(); st.force_full = false; }
        if need_full || st.last_input_len != input.len() { redraw_input(stdout, input); st.last_input_len = input.len(); }
        let _ = stdout.flush();
    }
    let mut draw_state = DrawState::new();
    fn push_msg(messages: &mut Vec<String>, st: &mut DrawState, msg: String) { messages.push(msg); st.force_full = true; }
    let mut status_msg = String::from("TUI started. Type /open <port> or /connect <token>. /exit to quit. [F2: 選択/コピーモード切替]");

    // スクロールと履歴状態
    let mut scroll_offset: usize = 0; // 0=最新 (一番下)。増えると過去へ。
    let mut history: Vec<String> = Vec::new();
    let mut history_pos: Option<usize> = None; // history 内のインデックス (0..len-1)。None は編集中の新規行。
    // VS Code 統合ターミナルでのマウス選択・コピー用モード
    // F2 でトグル: 有効時は MouseCapture を解除し、画面更新を止めて選択しやすくする
    let mut copy_mode: bool = false;

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
                                    render(&mut stdout, &messages, &input, &mut draw_state, scroll_offset, &status_msg);
                                }
                                _ => { /* 選択の邪魔をしない */ }
                            }
                            continue;
                        }
                        match code {
                            // F2 で選択/コピーモードに入る
                            KeyCode::F(2) => {
                                // 先に MouseCapture を解除（失敗時はステータスに表示）
                                let mut msg = "選択/コピーモード: マウスで選択し、Ctrl+Shift+C でコピー (VS Code)。F2 で復帰".to_string();
                                if let Err(e) = execute!(stdout, DisableMouseCapture) {
                                    msg = format!("選択/コピーモード: MouseCapture解除失敗: {e}");
                                }
                                status_msg = msg;
                                draw_state.force_full = true;
                                copy_mode = true;
                                // 案内を描画（この直後からはループ末尾の描画は抑止される）
                                render(&mut stdout, &messages, &input, &mut draw_state, scroll_offset, &status_msg);
                            }
                            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => { running = false; }
                            KeyCode::Char(ch) => { input.push(ch); redraw_input(&mut stdout, &input); }
                            KeyCode::Backspace => { input.pop(); redraw_input(&mut stdout, &input); }
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
                                        } else { status_msg = "Usage: /open <port>".into(); draw_state.force_full = true; }
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
                                        } else { status_msg = "Usage: /connect <token>".into(); draw_state.force_full = true; }
                                    }
                                    
                                    Some("/exit") => {
                                        status_msg = "Exiting...".into(); draw_state.force_full = true;
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
                                        if let Some(ref tx) = active_thread_tx { tx.send("/peers".into()).ok(); } else { status_msg = "No network thread.".into(); draw_state.force_full = true; }
                                    }
                                    Some("/close") => {
                                        if let Some(ref tx) = active_thread_tx { tx.send("/close".into()).ok(); } else { status_msg = "No network thread.".into(); draw_state.force_full = true; }
                                    }
                                    Some("/disconnect") => {
                                        if parts.len() < 2 { status_msg = "Usage: /disconnect <id>".into(); draw_state.force_full = true; }
                                        else if let Some(ref tx) = active_thread_tx { tx.send(format!("/disconnect {}", parts[1])).ok(); } else { status_msg = "No network thread.".into(); draw_state.force_full = true; }
                                    }
                                    Some("/dm") => {
                                        if parts.len() < 3 { status_msg = "Usage: /dm <to_id> <message>".into(); draw_state.force_full = true; }
                                        else if let Some(ref tx) = active_thread_tx { let to_id=&parts[1]; let value=parts[2..].join(" "); tx.send(format!("/dm {} {}", to_id, value)).ok(); } else { status_msg = "No network thread.".into(); draw_state.force_full = true; }
                                    }
                                    Some("/certs") => { if let Some(ref tx) = active_thread_tx { tx.send("/certs".into()).ok(); } else { status_msg = "No network thread.".into(); draw_state.force_full = true; } }
                                    Some("/cert") => { if parts.len()<2 { status_msg = "Usage: /cert <id>".into(); draw_state.force_full = true; } else if let Some(ref tx)=active_thread_tx { tx.send(format!("/cert {}", parts[1])).ok(); } else { status_msg = "No network thread.".into(); draw_state.force_full = true; } }
                                    Some(other) => {
                                        if other.starts_with('/') { status_msg = format!("Unknown command: {}", other); draw_state.force_full = true; }
                                        else if let Some(ref tx) = active_thread_tx { tx.send(format!("/msg {}", line)).ok(); } else { status_msg = "No network thread.".into(); draw_state.force_full = true; }
                                    }
                                    None => {}
                                }
                                input.clear(); redraw_input(&mut stdout, &input);
                                if !line.is_empty() { history.push(line); history_pos = None; }
                            }
                            KeyCode::Esc => { input.clear(); redraw_input(&mut stdout, &input); history_pos = None; }
                            KeyCode::Up => {
                                if history.is_empty() { continue; }
                                let new_pos = match history_pos { None => history.len().saturating_sub(1), Some(p) => p.saturating_sub(1) };
                                history_pos = Some(new_pos);
                                input = history[new_pos].clone();
                                redraw_input(&mut stdout, &input);
                            }
                            KeyCode::Down => {
                                if history.is_empty() { continue; }
                                if let Some(p) = history_pos {
                                    if p + 1 < history.len() { history_pos = Some(p+1); input = history[p+1].clone(); }
                                    else { history_pos = None; input.clear(); }
                                    redraw_input(&mut stdout, &input);
                                }
                            }
                            KeyCode::Left | KeyCode::Right | KeyCode::Tab => {}
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
            render(&mut stdout, &messages, &input, &mut draw_state, scroll_offset, &status_msg);
        }
    }

    // クリーンアップ
    execute!(stdout, DisableMouseCapture, LeaveAlternateScreen).ok();
    disable_raw_mode().ok();
    println!("Goodbye!");
}

fn run_network(tx_main: Sender<String>, rx_thread: Receiver<String>) {
    tx_main.send("network thread started".to_string()).ok();
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
            if cmd == "/exit" { tx_main.send("/exit received -> shutting down".to_string()).ok(); return; }
            if let Some(rest) = cmd.strip_prefix("/open ") {
                if listener.is_some() {
                    tx_main.send("already listening (only one /open allowed)".into()).ok();
                } else {
                    match TcpListener::bind(format!("127.0.0.1:{}", rest)) {
                        Ok(l) => { 
                            l.set_nonblocking(true).ok(); 
                            listener = Some(l); 
                            let addr = format!("127.0.0.1:{}", rest);
                            let tok = crypto::encrypt_conninfo_to_hex(&addr).unwrap_or_else(|_| "?".into());
                            tx_main.send(format!("Listening (token={})", tok)).ok(); 
                        }
                        Err(e) => { tx_main.send(format!("Bind error: {:?}", e)).ok(); }
                    }
                }
            } else if let Some(rest) = cmd.strip_prefix("/connect ") {
                // トークンのみ受け付け。復号失敗ならエラー
                let target = match crypto::decrypt_conninfo_from_hex(rest) { Ok(s) => s, Err(e) => { tx_main.send(format!("Connect token decrypt error: {}", e)).ok(); continue; } };
                match TcpStream::connect(&target) {
                    Ok(s) => { let s=s; s.set_nonblocking(true).ok(); clients.push(s); decoders.push(protocol::Decoder::new()); peer_meta.push(None); tx_main.send(format!("Connected (token={}) id={}", rest, clients.len()-1)).ok(); }
                    Err(e) => { tx_main.send(format!("Connect error (token={}): {:?}", rest, e)).ok(); }
                }
            } else if cmd == "/close" {
                if listener.is_some() { listener = None; tx_main.send("listener closed".into()).ok(); } else { tx_main.send("no active listener".into()).ok(); }
            } else if let Some(rest) = cmd.strip_prefix("/disconnect ") {
                if let Ok(id) = rest.trim().parse::<usize>() {
                    if id < clients.len() { clients.remove(id); decoders.remove(id); peer_meta.remove(id); tx_main.send(format!("disconnected id {}", id)).ok(); }
                    else { tx_main.send(format!("disconnect: invalid id {}", id)).ok(); }
                } else { tx_main.send(format!("disconnect: parse error '{}': expected number", rest)).ok(); }
            } else if cmd == "/peers" {
                let mut lines = Vec::new();
                lines.push(format!("peers total={} listening={}", clients.len(), listener.is_some()));
                for (i, c) in clients.iter().enumerate() {
                    let addr = c.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into());
                    let tok = crypto::encrypt_conninfo_to_hex(&addr).unwrap_or_else(|_| "?".into());
                    let fp = peer_meta.get(i).and_then(|m| m.as_ref()).map(|m| {
                        let d = ring::digest::digest(&ring::digest::SHA256, &m.public_key);
                        let h = crypto::to_hex(d.as_ref());
                        format!("fingerprint={}", &h[..16])
                    }).unwrap_or_else(|| "fingerprint=?".into());
                    lines.push(format!("id={} token={} {}", i, tok, fp));
                }
                tx_main.send(lines.join("\n")).ok();
            } else if cmd == "/certs" {
                let mut lines = vec!["certs:".to_string()];
                for (i, meta) in peer_meta.iter().enumerate() {
                    match meta {
                        Some(m) => {
                            let d = ring::digest::digest(&ring::digest::SHA256, &m.public_key);
                            let h = crypto::to_hex(d.as_ref());
                            lines.push(format!("id={} valid={} ts={} pk_len={} fingerprint={}", i, m.last_valid, m.last_timestamp, m.public_key.len(), &h[..32]));
                        }
                        None => lines.push(format!("id={} <no-key>", i)),
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
                                tx_main.send(format!("cert id={} valid={} ts={} pubkey={} fingerprint={}", id, m.last_valid, m.last_timestamp, crypto::to_hex(&m.public_key), h)).ok();
                            }
                            None => { tx_main.send(format!("cert id={} no key yet", id)).ok(); }
                        }
                    } else { tx_main.send(format!("cert: invalid id {}", id)).ok(); }
                } else { tx_main.send(format!("cert: parse error '{}'", rest)).ok(); }
            } else if let Some(rest) = cmd.strip_prefix("/msg ") {
                // 送信メッセージをプロトコルフレーム化
                if let (Some(ref pk), Some(ref pubk)) = (pkcs8.as_ref(), public.as_ref()) {
                    if let Some(m) = build_signed_chat(rest, pk, pubk) {
                        let frame = protocol::encode(&m);
                        let mut remove = Vec::new();
                        for (i, c) in clients.iter_mut().enumerate() {
                            if let Err(e) = c.write_all(&frame) { tx_main.send(format!("Write error to {}: {:?}", i, e)).ok(); remove.push(i); }
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
                                if let Err(e) = clients[target].write_all(&frame) { tx_main.send(format!("DM write error to {}: {:?}", target, e)).ok(); }
                            } else { tx_main.send("DM署名生成失敗".into()).ok(); }
                        } else { tx_main.send("鍵未生成 (/init を先に実行)".into()).ok(); }
                    } else {
                        tx_main.send(format!("DM target id {} out of range", target)).ok();
                    }
                } else {
                    tx_main.send(format!("Invalid dm target: {}", to)).ok();
                }
            } else if !cmd.is_empty() {
                // 旧テキスト互換は廃止: 非コマンド入力は /msg 側で処理される
            }
        }

        // accept
        if let Some(l) = &listener {
            loop {
                match l.accept() {
                    Ok((s, peer)) => { let s=s; s.set_nonblocking(true).ok(); clients.push(s); decoders.push(protocol::Decoder::new()); peer_meta.push(None); let token = crypto::encrypt_conninfo_to_hex(&peer.to_string()).unwrap_or_else(|_| "?".to_string()); tx_main.send(format!("Accepted (token={}) id={}", token, clients.len()-1)).ok(); }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => { tx_main.send(format!("Accept error: {:?}", e)).ok(); break; }
                }
            }
        }

        // 読み取り (バイナリプロトコル優先)
        let mut received_frames: Vec<(usize, protocol::Message)> = Vec::new();
        let mut remove_indices: Vec<usize> = Vec::new();
        for (idx, c) in clients.iter_mut().enumerate() {
            match c.read(&mut buf) {
                Ok(0) => { tx_main.send(format!("Client {} closed", idx)).ok(); remove_indices.push(idx); }
                Ok(n) => { if n>0 { decoders[idx].feed(&buf[..n]); if let Ok(mut msgs) = decoders[idx].drain() { for m in msgs.drain(..) { received_frames.push((idx, m)); } } } }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => { tx_main.send(format!("Read error {}: {:?}", idx, e)).ok(); remove_indices.push(idx); }
            }
        }

        // 中継と表示 + 署名検証
        for (src, msg) in received_frames.iter() {
            let txt = String::from_utf8_lossy(&msg.payload);
            let mut signed_state = if msg.signature.is_some() { "signed" } else { "plain" };
            let mut good = true;
            if let (Some(sig), Some(pk)) = (msg.signature.as_ref(), msg.public_key.as_ref()) {
                // 検証 (public_key & signature は署名対象外領域)
                let minimal = protocol::Message { version: msg.version, kind: msg.kind, payload: msg.payload.clone(), timestamp: msg.timestamp, public_key: None, signature: None };
                let data = protocol::signing_bytes(&minimal);
                if crypto::verify_ed25519(&data, sig, pk).is_err() { signed_state = "bad-signature"; good = false; }
                // メタ更新
                if *src < peer_meta.len() { peer_meta[*src] = Some(PeerMeta { public_key: pk.clone(), last_valid: good, last_timestamp: msg.timestamp }); }
            }
            if msg.kind == protocol::MsgKind::DM {
                tx_main.send(format!("DM!! from:{} {} [{}]", src, txt, signed_state)).ok();
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
