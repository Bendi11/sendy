use std::sync::Arc;

use rsa::{
    pkcs1v15::{DecryptingKey, SigningKey},
    sha2::Sha256,
};

use crate::{net::sock::ReliableSocket, model::crypto::PrivateKeychain};

/// Shared state used to execute all peer to peer operations
#[derive(Debug)]
pub struct Context {
    /// Manager for all peer connections
    pub(crate) socks: Arc<ReliableSocket>,
    /// Collection of the host's crypto keys
    keychain: PrivateKeychain,
}
