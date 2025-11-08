## 概要
このリポジトリはローカルで動作する分散型/TUI クライアント（Rust製）です。AI エージェントが素早く貢献できるよう、実装の要点・開発ワークフロー・コードパターンを短くまとめます。

## すぐに使うコマンド
- ビルド: `cargo build`
- チェック: `cargo check`
- 実行 (デバッグ): `cargo run --`  (TUI のため端末で実行してください)

注: `src/main.rs` は crossterm を使ったフルスクリーン TUI を生成します。VS Code のデバッガで直接走らせると入力/画面周りで問題が出るため、まずは端末での実行を推奨します。

## アーキテクチャの“短い”説明
- UI / メインスレッド: `src/main.rs` — TUI レンダリング、ユーザ入力受付、コマンドパーサ（例: `/open`, `/connect`, `/msg`, `/dm`, `/init`）。
- 設定管理: `src/config.rs` — グローバルな `CONFIG: OnceLock<RwLock<Table>>` を使い、`config.toml` を読み書きします。`config::upsert_value_and_save` はメモリ更新→ファイル保存→再読み込みの順で整合性を保ちます。
- 暗号処理: `src/crypto.rs` — Ed25519 鍵生成/署名/検証、ChaCha20-Poly1305 を使った簡易暗号化（`CONNINFO_KEY` を共通鍵として利用）。
- プロトコル: `src/protocol.rs` — バイナリフレームフォーマット（ヘッダ22バイト + 可変長 public/signature/payload）、`Decoder` ストリーミング実装、`signing_bytes` の定義（署名対象のバイト列）。

## 重要な設計上のポイント（AI が直す/追加する時に注意）
- 設定はグローバルシングルトン (`OnceLock<RwLock<...>>`)。初期化は `config::init_config_path("./config.toml")` を必ず呼ぶこと。
- ハンドル（ユーザ名）は `@` で始まり 80 文字未満という制約がコードにハードコードされています（`src/main.rs` の `handle` チェック）。
- ネットワーク操作はメインスレッドから文字列コマンドでワーカーに渡す（mpsc チャンネル）。ワーカーは `/open`, `/connect`, `/peers` 等の文字列を受け取り処理します。直接ソケットや低レベルコードを編集する場合、このコマンド文字列フォーマットと整合性を保ってください。
- 署名対象とフレームレイアウトは `src/protocol.rs` に明記されています。署名生成は `crypto::sign_ed25519(signing_bytes(&msg), pkcs8)` のように行われます。誤ったバイト列で署名すると検証失敗になります。

## 具体的なコード例（参照してください）
- 署名付きチャット作成: `src/main.rs` の `build_signed_chat(text, pkcs8, pubk)` を参照。内部で `protocol::signing_bytes` を使い `crypto::sign_ed25519` で署名して `with_key_sig` しています。
- DM 暗号化: `crypto::encrypt_dm_payload` / `crypto::decrypt_dm_payload`。フォーマットは `nonce(12B) || ciphertext || tag(16B)`。
- 接続トークンの暗号化: `crypto::encrypt_conninfo_to_hex` / `decrypt_conninfo_from_hex` を利用。トークンは `nonce || ciphertext+tag` を hex にした文字列として扱われます。

## PR / 編集の指針（AI 向け）
- 変更は小さく、1 PR = 1目的（例: プロトコルのフィールド追加、設定の不具合修正）。
- 設定ファイルや鍵（`config.toml` の `key.pkcs8`）に触れる変更はドキュメント化し、既存の保存/再読み込みの流れを壊さないこと。
- TUI の表示ロジックを変える場合、端末で `cargo run --` を使い手動で目視確認してください（自動テストは存在しません）。

## ファイル参照（必読）
- `src/main.rs` — コマンド一覧、TUI 描画、メッセージ整形、メインの入出力ループ。
- `src/protocol.rs` — フレームレイアウト、`Decoder`、`signing_bytes`。
- `src/crypto.rs` — 鍵/署名/暗号化ユーティリティ、`CONNINFO_KEY`（固定鍵、テスト用途）。
- `src/config.rs` — `init_config_path`, `get_value`, `upsert_value_and_save`, `save` の動作。
- `config.toml` — デフォルトの設定と鍵の保存場所。新しい鍵は `/init` コマンドで生成され `key.pkcs8` に hex で保存されます。