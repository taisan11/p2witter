# p2witter
個人個人がクライアントを起動しとく分散型SNSです。  
速い話、Winnyやtrentと似たような仕組みを持ったSNSです。
けど、MisskeyやBlueSky見たいに実用的なSNSに仕上げていきたいです。  
又、外出先からリモートクライアントにアクセスする機能は `/tunnel` で提供済み（ngrok / serveo 対応）です。
ctrl+cとかしたら多分バグるからちゃんと/exitしてね
えっ?固まって動かない?ターミナルエミュレータ事終了すれば万事解決だね!!
## config.toml
これがすべての設定を司るテキストファイルです。  
`key`の中には`pkcs8`と`public`があり、大事な鍵を保管しています。  
`pkcs8`が流出したらなりすましできるので気を付けましょう。

### ネットワーク・トンネル関連の設定
```toml
[network]
# /open で public-host を省略した際のフォールバック公開アドレス。
# 空なら 127.0.0.1（ローカル/LAN）になる。トンネル利用時はここに
# "host:port" を書くか、/open <port> <public-host> で都度指定する。
advertise_host = ""

[tunnel]
# デフォルトのトンネルプロバイダ（空なら未設定）。/tunnel で上書き可能。
provider = ""
# ngrok の authtoken（任意）。空なら未指定。
ngrok_authtoken = ""
```

## トンネル越しの接続（外部IPと内部IPが異なる環境）
P2Witter は生 TCP で通信するため、外部から到達可能な TCP 転送トンネルを使えば
NAT/ファイアウォール越しに接続できます。対応プロバイダは `src/core/tunnel` に実装。

- `ngrok`：`ngrok tcp <port>` で生 TCP 転送。`ngrok_authtoken` で認証可。
- `serveo`：`ssh -R 0:localhost:<port> serveo.net` で生 TCP 転送（要 ssh クライアント）。

使い方：
```
/tunnel ngrok 8080        # トンネル起動 → 公開アドレスを自動で /open に渡す
/tunnel serveo 8080       # 同上
/open 8080 1.tcp.ngrok.io:12345   # トンネル端点を明示して広告
/open 8080                # advertise_host 未設定なら 127.0.0.1（LAN内のみ）
```
`/open` が表示するトークンには上記の公開アドレスが載るので、相手はそのトークンを
`/connect <token>` に渡すだけで届きます（生の `host:port` は `/connect` では指定不可）。

### 二重接続の自動解消
外部/内部IPが異なる環境では、A→B と B→A の両方向から接続が生じ「同一ピアへの
二重接続」が起こり得ます。P2Witter は HELLO ハンドシェイク時に相手の Ed25519 公開鍵で
重複を検出し、両端で対称に「1本のリンクだけ残る」ように解消します（メッセージの
重複検出 `seen_messages` とも組み合わせてループを防止）。
## roadmap
- [x] bincodeからの移行を考える
- [x] 大規模ネットワーク用のメッセージ減衰処理
- [x] 自動テストの実装（`src/bin/p2wtest` で複数クライアントを実TCPループバックで動かす）
- [x] プロトコルの安定化

## p2wtest（ネットワーク実験/テスト用バイナリ）
複数クライアントを1プロセス内で実際に起動し、実TCPループバック経由で
`network_handler` を動かす実験・テストツールです。各クライアントは固有の
設定(鍵/ハンドル)と sled データベースを持ち、グローバルな singleton を共有しません。

```
cargo run --bin p2wtest -- <scenario> [options]
```

シナリオ:
- `two-clients` : 2ノード接続＋チャット中継
- `three-relay` : 3ノード(A-B-C)チェーンでの中継
- `invalid-hello` : 不正署名HELLO → 切断
- `invalid-handle` : ハンドル長超過HELLO → 切断
- `invalid-chat-handle` : 超長ハンドルを含むCHAT → 切断
- `scale20 --nodes N --seed S --duration SEC --fanout K` : ランダムNノード網で自動実験
  （ランダムな送信元から投稿し到達率を集計、さらに不正ノードを注入して検知を確認）

失敗時は終了コード 1 で終了します。
