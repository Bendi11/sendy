mod net;
mod ser;
mod crypto;


use std::sync::Arc;

use crypto::PrivateKeychain;
use net::sock::{ReliableSocket, SocketConfig};
pub use ser::{FromBytes, FromBytesError, ToBytes};


/// The main interface for interacting with the Sendy network - contains state for all peer
/// connections and resource persistence
#[derive(Debug,)]
pub struct Context {
    /// Manager for all lower-level UDP operations
    socks: ReliableSocket,
    /// Keychain used to sign and encrypt messages
    keychain: PrivateKeychain,
}

impl Context {
    /// Create a new `Context` with the given keychain for authentication and encryption
    pub fn new(keychain: PrivateKeychain, cfg: SocketConfig) -> Arc<Self> {
        let socks = ReliableSocket::new(cfg);
        Arc::new(Self {
            socks,
            keychain,
        })
    }
}
