use std::net::SocketAddrV4;

use clap::Parser;
use sendy_framework::net::sock::ReliableSocket;

/// Test UDP connection on local network
#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Args {
    /// IP address of the peer to attempt a connection to
    #[arg(index=1)]
    addr: SocketAddrV4,

}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    stderrlog::new().verbosity(log::LevelFilter::Trace).init().unwrap();

    let args = Args::parse();

    ReliableSocket::tunnel_connect(args.addr).await.unwrap();
}
