use std::{sync::Arc, net::SocketAddr};

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
    keychain: PrivateKeychain,
}

/// Resource identifier tag
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    Certificate,
}

/// Resources are any data meant to be persisted on the sendy network, they must be signed by an
/// author and identifiable by a unique ID
pub trait Resource<'a>: ToBytes + FromBytes<'a> {
    const RESOURCE_KIND: ResourceKind;
    
    type Signature: ToBytes + FromBytes<'a>;

    fn validate(&self, buf: &'a [u8], signature: Self::Signature) -> bool;
    
    fn sign(&self, ctx: &Context);

    fn signature(&self) -> &Self::Signature;
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
    
    /// Connect to the peer at the given IP address and port
    pub async fn connect(&self, peer: SocketAddr) -> std::io::Result<()> {
        let tx = self.socks.create_transmitter(peer).await?;

        Ok(())
    }
}
