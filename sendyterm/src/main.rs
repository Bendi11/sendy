mod secret;
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use clap::{Parser, Subcommand};

use sendy_framework::{
    model::crypto::PrivateKeychain,
    rsa::{self, pkcs1v15::DecryptingKey},
    Context, SocketConfig,
};

#[derive(Parser)]
#[command(name = "sendy")]
#[command(about = "Terminal interface for the Sendy p2p chat")]
pub struct Cli {
    #[arg(short = 'k', long = "keystore")]
    #[arg(value_enum)]
    #[arg(default_value_t=KeyStore::PlainFile)]
    #[arg(help = "Method used to store private keys")]
    keystore: KeyStore,
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand)]
pub enum CliCommand {
    #[command(about = "Generate new RSA private keys and overwrite them in your secret storage")]
    #[command(name = "keygen")]
    KeyGen {
        #[arg(short = 's', long = "size")]
        #[arg(value_enum)]
        #[arg(default_value_t=RsaKeyWidth::Large)]
        bits: RsaKeyWidth,
    },
    #[command(about = "", name = "launch")]
    Run {
        #[arg(
            index = 2,
            name = "Username",
            help = "Username to display to other users"
        )]
        username: String,
        #[arg(
            index = 1,
            short = 'p',
            long = "hostip",
            help = "Public IP address of the local host"
        )]
        publicip: Ipv4Addr,
        #[arg(
            short = 'p',
            long = "ports",
            help = "A comma-separated list of ports to listen for connections on"
        )]
        ports: Vec<u16>,
    },
}

#[repr(usize)]
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum RsaKeyWidth {
    Large = 4096,
    Small = 2048,
}

/// Selection for how the private keychain is persisted between sessions
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum KeyStore {
    /// Store the private keychain as secrets using the secret service API
    #[cfg(target_os = "linux")]
    SecretService,
    /// Store the private keychain as unprotected PKCS#8 DER files
    PlainFile,
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

    let keystore = match args.keystore {
        KeyStore::PlainFile => &secret::DerFileStore as &dyn secret::SecretStore,
        #[cfg(target_os = "linux")]
        KeyStore::SecretService => &secret::SecretServiceStore as &dyn secret::SecretStore,
    };

    match args.command {
        CliCommand::KeyGen { bits } => {
            let mut rng = rsa::rand_core::OsRng::default();
            let signature = rsa::RsaPrivateKey::new(&mut rng, bits as usize).unwrap();
            let encrypt = rsa::RsaPrivateKey::new(&mut rng, bits as usize).unwrap();

            keystore
                .store(&PrivateKeychain::new(signature.into(), encrypt))
                .await;
        }
        CliCommand::Run {
            username,
            publicip,
            ports,
        } => {
            let keychain = match keystore.read().await {
                Some(kc) => kc,
                None => {
                    log::error!(
                        "Failed to get secret keys from store, generating them for session"
                    );
                    let mut rng = rsa::rand_core::OsRng::default();
                    let signature = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
                    let encrypt = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();

                    PrivateKeychain::new(signature.into(), encrypt)
                }
            };

            let ctx = Context::new(keychain, SocketConfig::default(), "USER".to_owned());

            for port in ports {
                if let Err(e) = ctx.listen(port).await {
                    log::error!("Failed to listen on port {port}: {}", e);
                }
            }

            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}
