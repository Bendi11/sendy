use std::{net::{SocketAddrV4, Ipv4Addr}, time::Duration};

use clap::Parser;

use sendy_framework::{rsa, model::crypto::PrivateKeychain, ctx::Context};

/// Test UDP connection on local network
#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Args {
    /// IP address of the peer to attempt a connection to
    #[arg(index = 1)]
    addr: SocketAddrV4,
    #[arg(long)]
    publicip: Ipv4Addr,
}

#[tokio::main]
async fn main() {
    stderrlog::new()
        .verbosity(log::LevelFilter::Trace)
        .init()
        .unwrap();

    let args = Args::parse();
        
    let mut rng = rsa::rand_core::OsRng::default();
    let bits = 4096;
    let signature = rsa::RsaPrivateKey::new(&mut rng, bits).unwrap();
    let encrypt = rsa::RsaPrivateKey::new(&mut rng, bits).unwrap();

    let keychain = PrivateKeychain::new(signature, encrypt);

    let ctx = Context::new(keychain, std::net::IpAddr::V4(args.publicip)).await;
    let _peer = ctx.connect(std::net::SocketAddr::V4(args.addr)).await.unwrap();

    tokio::time::sleep(Duration::from_secs(5)).await;
}
