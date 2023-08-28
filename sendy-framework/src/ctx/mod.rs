use std::{sync::Arc, net::SocketAddr};

use sqlx::SqlitePool;

use crate::{SocketConfig, ToBytes, FromBytes};
use crate::model::crypto::PrivateKeychain;
use crate::sock::ReliableSocket;

mod handle;

/// The main interface for interacting with the Sendy network - contains state for all peer
/// connections and resource persistence
#[derive(Debug)]
pub struct Context {
    /// Manager for all lower-level UDP operations
    socks: ReliableSocket,
    /// Keychain used to sign and encrypt messages
    pub(crate) keychain: PrivateKeychain,
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
        db: SqlitePool,
    ) -> Arc<Self> {
        let socks = ReliableSocket::new(cfg);

        if let Err(e) = sqlx::migrate!("../migrations").run(&db).await {
            log::error!("Failed to apply database migrations: {}", e);
        }

        Arc::new(Self { socks, keychain, db })
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
