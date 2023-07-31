use std::sync::Arc;

use rsa::{
    pkcs1v15::{DecryptingKey, SigningKey},
    sha2::Sha256,
};

use crate::net::sock::ReliableSocket;

/// Shared state used to execute all peer to peer operations
#[derive(Debug)]
pub struct Context {
    /// Manager for all peer connections
    pub(crate) socks: Arc<ReliableSocket>,
    /// Collection of the host's crypto keys
    keychain: Keychain,
}

/// A collection of cryptographic keys used to authenticate and encrypt messages
#[derive(Debug)]
struct Keychain {
    /// RSA keys used to sign messages that have been sent
    pub auth: SigningKey<Sha256>,
    /// RSA keys used to encrypt and decrypt messages for symmetric session key transfers
    pub enc: DecryptingKey,
}
