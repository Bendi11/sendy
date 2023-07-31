use std::{net::{SocketAddrV4, SocketAddr}, time::Duration};

use clap::Parser;
use sendy_framework::net::{
    msg::TestMessage,
    sock::{SocketConfig},
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

    tokio::time::sleep(Duration::from_secs(5)).await;
}
