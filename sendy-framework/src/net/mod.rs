use std::{sync::Arc, net::IpAddr};

use rsa::{RsaPrivateKey, RsaPublicKey};

use self::sock::ReliableSocket;

pub mod conn;
pub mod msg;
pub mod sock;

/// Shared state used to execute all peer to peer operations
#[derive(Clone, Debug)]
pub struct Context {
    /// Manager for all peer connections
    pub socks_manager: Arc<ReliableSocket>,
    /// The user's public and private keys (zeroized on drop)
    pub key: RsaPrivateKey,
}
