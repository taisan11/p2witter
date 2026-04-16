//! Test utilities for p2witter
//!
//! Provides helper functions for creating mesh networks using tokio::io::duplex

use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// Represents a node in the test mesh network
pub struct MeshNode {
    pub id: usize,
    pub stream: DuplexStream,
}

/// Represents a connection between two nodes
pub struct MeshConnection {
    pub from: usize,
    pub to: usize,
}

/// Creates a duplex mesh network with the specified number of nodes
///
/// Returns a HashMap where each node ID maps to a vector of its connections.
/// Each connection is a bidirectional DuplexStream.
///
/// # Example
/// ```
/// let mesh = create_duplex_mesh(3, vec![
///     (0, 1), // Node 0 connects to Node 1
///     (1, 2), // Node 1 connects to Node 2
/// ]);
/// ```
pub fn create_duplex_mesh(
    num_nodes: usize,
    connections: Vec<(usize, usize)>,
) -> HashMap<usize, Vec<DuplexStream>> {
    let mut node_streams: HashMap<usize, Vec<DuplexStream>> = HashMap::new();

    // Initialize empty vectors for each node
    for i in 0..num_nodes {
        node_streams.insert(i, Vec::new());
    }

    // Create duplex streams for each connection
    for (from, to) in connections {
        let (stream_a, stream_b) = tokio::io::duplex(8192);

        // Add streams to both nodes
        if let Some(streams) = node_streams.get_mut(&from) {
            streams.push(stream_a);
        }
        if let Some(streams) = node_streams.get_mut(&to) {
            streams.push(stream_b);
        }
    }

    node_streams
}

/// Creates a full mesh network where every node connects to every other node
///
/// Returns a HashMap where each node ID maps to a vector of its connections.
///
/// # Example
/// ```
/// let mesh = create_full_mesh(3); // Creates connections: 0-1, 0-2, 1-2
/// ```
pub fn create_full_mesh(num_nodes: usize) -> HashMap<usize, Vec<DuplexStream>> {
    let mut connections = Vec::new();

    // Create all possible pairs
    for i in 0..num_nodes {
        for j in (i + 1)..num_nodes {
            connections.push((i, j));
        }
    }

    create_duplex_mesh(num_nodes, connections)
}

/// Creates a linear chain network where nodes are connected in a line
///
/// Returns a HashMap where each node ID maps to a vector of its connections.
/// Example: 0 - 1 - 2 - 3
///
/// # Example
/// ```
/// let mesh = create_chain_mesh(4); // Creates connections: 0-1, 1-2, 2-3
/// ```
pub fn create_chain_mesh(num_nodes: usize) -> HashMap<usize, Vec<DuplexStream>> {
    let mut connections = Vec::new();

    // Create chain: 0-1, 1-2, 2-3, ...
    for i in 0..(num_nodes.saturating_sub(1)) {
        connections.push((i, i + 1));
    }

    create_duplex_mesh(num_nodes, connections)
}

/// Creates a star network where one central node connects to all others
///
/// Returns a HashMap where each node ID maps to a vector of its connections.
/// Node 0 is the central hub.
///
/// # Example
/// ```
/// let mesh = create_star_mesh(4); // Creates connections: 0-1, 0-2, 0-3
/// ```
pub fn create_star_mesh(num_nodes: usize) -> HashMap<usize, Vec<DuplexStream>> {
    let mut connections = Vec::new();

    // Create star: 0-1, 0-2, 0-3, ...
    for i in 1..num_nodes {
        connections.push((0, i));
    }

    create_duplex_mesh(num_nodes, connections)
}

/// Helper to send a message through a duplex stream
pub async fn send_message(stream: &mut DuplexStream, msg: &[u8]) -> std::io::Result<()> {
    stream.write_all(msg).await?;
    stream.flush().await?;
    Ok(())
}

/// Helper to receive a message from a duplex stream with timeout
pub async fn recv_message(stream: &mut DuplexStream, buf: &mut [u8]) -> std::io::Result<usize> {
    stream.read(buf).await
}

/// Helper to receive a message with a specified timeout
pub async fn recv_message_timeout(
    stream: &mut DuplexStream,
    buf: &mut [u8],
    timeout: std::time::Duration,
) -> std::io::Result<usize> {
    match tokio::time::timeout(timeout, stream.read(buf)).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "read timeout",
        )),
    }
}
