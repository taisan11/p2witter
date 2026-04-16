mod common;

use common::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

#[tokio::test]
#[ignore]
async fn super_test() {
    // ノードA と ノードB の2つのノードを duplex で接続
    let mut mesh = create_duplex_mesh(2, vec![(0, 1)]);

    let mut node_a_streams = mesh.remove(&0).unwrap();
    let mut node_b_streams = mesh.remove(&1).unwrap();

    assert_eq!(node_a_streams.len(), 1, "Node A should have 1 connection");
    assert_eq!(node_b_streams.len(), 1, "Node B should have 1 connection");

    let mut stream_a = node_a_streams.pop().unwrap();
    let mut stream_b = node_b_streams.pop().unwrap();

    // ノードB から ノードA にメッセージを送信
    let msg = b"Hello from Node B";
    let send_task = tokio::spawn(async move {
        stream_b.write_all(msg).await.unwrap();
        stream_b.flush().await.unwrap();
        stream_b
    });

    // ノードA でメッセージを受信
    let mut buf = [0u8; 1024];
    let n = stream_a.read(&mut buf).await.unwrap();

    assert_eq!(&buf[..n], msg, "Message not received correctly");

    // クリーンアップ
    send_task.await.unwrap();
}
