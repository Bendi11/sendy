mod net;
mod ser;

pub mod model;

use std::sync::Arc;

use model::crypto::PrivateKeychain;
use net::sock::ReliableSocket;
pub use net::sock::SocketConfig;
pub use rsa;
pub use ser::{FromBytes, FromBytesError, ToBytes};

/// The main interface for interacting with the Sendy network - contains state for all peer
/// connections and resource persistence
#[derive(Debug)]
pub struct Context {
    /// Manager for all lower-level UDP operations
    socks: ReliableSocket,
    /// Keychain used to sign and encrypt messages
    keychain: PrivateKeychain,
}

impl Context {
    /// Create a new `Context` with the given keychain for authentication and encryption
    pub fn new(keychain: PrivateKeychain, cfg: SocketConfig, username: String) -> Arc<Self> {
        let socks = ReliableSocket::new(cfg);
        Arc::new(Self { socks, keychain })
    }

    /// Listen for incoming connections on the given port
    #[inline]
    pub async fn listen(&self, port: u16) -> std::io::Result<()> {
        self.socks.new_binding(port).await
    }
}
