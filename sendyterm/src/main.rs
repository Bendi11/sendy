mod secret;
use std::{net::{SocketAddrV4, Ipv4Addr}, time::Duration};

use clap::{Parser, Subcommand, builder::PossibleValuesParser};

use sendy_framework::{rsa, model::crypto::PrivateKeychain, ctx::Context};

#[derive(Parser)]
#[command(name = "sendy")]
#[command(about = "Terminal interface for the Sendy p2p chat")]
pub struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand)]
pub enum CliCommand {
    #[command(about = "Generate new RSA private keys and overwrite them in your secret storage")]
    KeyGen {
        #[arg(short='s',long="size")]
        #[arg(value_enum)]
        #[arg(default_value_t=RsaKeyWidth::Large)]
        bits: RsaKeyWidth,
    },
    #[command(about = "Connect to the remote peer at the given address using keys strored in the secret storage")]
    Connect {
        #[arg(index=1, name="PEER", help="IP address and port of the remote peer")]
        peer: SocketAddrV4,
        #[arg(short='h', long="hostip", help="Public IP address of the local host")]
        publicip: Ipv4Addr,
    }
}

#[repr(usize)]
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum RsaKeyWidth {
    Large = 4096,
    Small = 2048,
}

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

    let args = Cli::parse();

    match args.command {
        CliCommand::KeyGen { bits } => {
            let mut rng = rsa::rand_core::OsRng::default();
            let signature = rsa::RsaPrivateKey::new(&mut rng, bits as usize).unwrap();
            let encrypt = rsa::RsaPrivateKey::new(&mut rng, bits as usize).unwrap();

            secret::SECRET_STORE.store(&PrivateKeychain::new(signature, encrypt)).await;
        },
        CliCommand::Connect { peer, publicip } => {
            let Some(keychain) = secret::SECRET_STORE.read().await else {
                log::error!("Failed to get secret keys from store");
                return
            };
            
            let ctx = Context::new(keychain, std::net::IpAddr::V4(publicip)).await;
            let _peer = ctx.connect(std::net::SocketAddr::V4(peer)).await.unwrap();

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}
