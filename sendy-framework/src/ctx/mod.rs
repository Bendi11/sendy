use std::net::Ipv4Addr;
use std::{sync::Arc, net::SocketAddr};
use signature::Signer;

use chrono::{Utc, Duration};
use sqlx::SqlitePool;

use crate::model::cert::{PeerCertificate, UnsignedPeerCertificate, PeerCapabilities};
use crate::{SocketConfig, ToBytes};
use crate::model::crypto::PrivateKeychain;
use crate::sock::ReliableSocket;

mod handle;
pub mod res;

pub use res::Resource;

/// The main interface for interacting with the Sendy network - contains state for all peer
/// connections and resource persistence
#[derive(Debug)]
pub struct Context {
    /// Manager for all lower-level UDP operations
    socks: ReliableSocket,
    /// Keychain used to sign and encrypt messages
    pub(crate) keychain: PrivateKeychain,
    /// Signed certificate for our keys
    pub(crate) certificate: PeerCertificate,
    /// Connection to an sqlite database used to store all resources
    pub(crate) db: SqlitePool,
}


impl Context {
    /// Create a new `Context` with the given keychain for authentication and encryption,
    /// configuration options, and database connection pool for resource storage
    pub async fn new(
        keychain: PrivateKeychain,
        cfg: SocketConfig,
        username: String,
    ) -> Result<Arc<Self>, sqlx::Error> {
        let socks = ReliableSocket::new(cfg);
        
        let db = sqlx::SqlitePool::connect("sqlite://./sendy.db?mode=rwc").await?;
        sqlx::migrate!("../migrations").run(&db).await?;

        let certificate = UnsignedPeerCertificate {
            keychain: keychain.public(),
            sockaddr: std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            username,
            capabilities: PeerCapabilities::all(),
            timestamp: Utc::now(),
            ttl: Duration::seconds(900),
        };

        let certificate = {
            let bytes = match certificate.encode_to_vec() {
                Ok(v) => v,
                Err(e) => {
                    panic!("Failed to encode host certificate: {}", e);
                }
            };
            let signature = keychain.authentication.sign(&bytes);
            PeerCertificate {
                cert: certificate,
                signature,
            }
        };

        let this = Arc::new(Self { socks, keychain, certificate: certificate.clone(), db });


        let id = PeerCertificate::store(&this, certificate).await.unwrap();
        log::trace!("ID is {:x}", id);

        log::trace!("signature is {:x}", PeerCertificate::fetch(&this, id).await.unwrap().signature);

        Ok(this)

    }

    /// Listen for incoming connections on the given port
    #[inline]
    pub async fn listen(&self, port: u16) -> std::io::Result<()> {
        self.socks.new_binding(port).await
    }
    
    /// Connect to the peer at the given IP address and port
    pub async fn connect(&self, peer: SocketAddr) -> std::io::Result<()> {
        let tx = self.socks.create_transmitter(peer).await?;

        Ok(())
    }
}
