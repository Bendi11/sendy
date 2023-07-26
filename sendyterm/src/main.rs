use std::{net::SocketAddrV4, time::Duration};

use clap::Parser;
use sendy_framework::net::{sock::ReliableSocket, packet::TestMessage};

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
        .verbosity(log::LevelFilter::Trace)
        .init()
        .unwrap();

    let args = Args::parse();

    let sock = ReliableSocket::tunnel_connect(args.addr).await.unwrap();
    sock.send(TestMessage { buf: (0..10000).map(|idx| format!("{}\n", idx)).collect::<String>() } ).await.unwrap();
    let (_, msg) = sock.recv().await;
    println!("Received: {}", String::from_utf8_lossy(&msg));

    tokio::time::sleep(Duration::from_secs(5)).await;
}
