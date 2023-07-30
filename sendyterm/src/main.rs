use std::{net::{SocketAddrV4, SocketAddr}, time::Duration};

use clap::Parser;
use sendy_framework::net::{
    msg::TestMessage,
    sock::{ReliableSocket, SocketConfig},
};

/// Test UDP connection on local network
#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Args {
    /// IP address of the peer to attempt a connection to
    #[arg(index = 1)]
    addr: SocketAddrV4,
}

#[tokio::main]
async fn main() {
    stderrlog::new()
        .verbosity(log::LevelFilter::Warn)
        .init()
        .unwrap();

    let args = Args::parse();

    let sock = ReliableSocket::new(SocketConfig::default())
        .await;

    let conn = sock.connect(SocketAddr::V4(args.addr)).await.unwrap();

    conn.send(TestMessage(
        (0..19_000_000u32)
            .map(|v| v.to_le_bytes()[0])
            .collect::<Vec<u8>>(),
    ))
    .await
    .unwrap();

    let msg = conn.recv().await;
    println!("{}", String::from_utf8_lossy(&msg.bytes));

    tokio::time::sleep(Duration::from_secs(5)).await;
}
