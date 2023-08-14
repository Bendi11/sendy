use std::net::SocketAddr;

use bytes::Bytes;
use futures::Future;
use sha2::{Sha256, Digest};
use rsa::pkcs8::EncodePublicKey;

use crate::{
    ctx::ContextInternal,
    model::crypto::{PublicKeychain, SignedCertificate, UserId},
    net::{
        msg::{MessageKind, ReceivedMessage},
        sock::{PacketKind, ReliableSocketConnection},
    },
    req::{Request, Response},
};

/// A connection to a remote peer over UDP, with state retrieved from a connection handshake
#[derive(Debug)]
pub struct Peer {
    pub(crate) conn: ReliableSocketConnection,
    /// The certificate of this peer, including public keys that can be used to encrypt and
    /// validate messages the peer sends
    pub(crate) cert: SignedCertificate,
}

impl Peer {
    /// Get the signed certificate of this peer
    pub const fn certificate(&self) -> &SignedCertificate {
        &self.cert
    }

    /// Shortcut for `certificate().cert().keychain()`
    #[inline(always)]
    pub const fn remote_keys(&self) -> &PublicKeychain {
        self.certificate().cert().keychain()
    }
    
    /// Compute the user ID of this peer by the hash of their public key
    pub fn id(&self) -> Result<UserId, rsa::pkcs8::spki::Error> {
        let mut hasher = Sha256::new();
        let bytes = self.remote_keys().auth.to_public_key_der()?;
        hasher.update(bytes.as_bytes());
        let hash = hasher.finalize();

        Ok(UserId(hash.into()))
    }
}

impl Peer {
    /// Disconnect from this peer
    pub(crate) async fn disconnect(self, ctx: &ContextInternal) -> std::io::Result<()> {
        let _ = ctx
            .socks
            .send_wait_response(&self.conn, MessageKind::Terminate, ())
            .await?
            .await;

        ctx.authenticated_peers.remove(&self.remote().ip());
        Ok(())
    }

    /// Get the IP address and port of the connected peer
    pub const fn remote(&self) -> &SocketAddr {
        self.conn.remote()
    }
    
    /// Get the signed certificate of the peer
    pub const fn cert(&self) -> &SignedCertificate {
        &self.cert
    }

    /// Send the given request message and await a response from the remote
    #[inline]
    pub(crate) async fn send_wait_response<'a, R: Request>(
        &'a self,
        ctx: &'a ContextInternal,
        msg: &'a R,
    ) -> std::io::Result<impl Future<Output = Bytes> + 'a> {
        ctx.socks
            .send_wait_response(
                &self.conn,
                R::KIND,
                msg,
            )
            .await
    }

    /// Respond to the given request message with a payload only, no message kind needed
    #[inline]
    pub(crate) async fn respond<R: Response>(
        &self,
        ctx: &ContextInternal,
        req: &ReceivedMessage,
        response: &R,
    ) -> std::io::Result<()> {
        ctx.socks
            .send_with_id(
                &self.conn,
                req.id,
                PacketKind::Message(MessageKind::Respond),
                response,
            )
            .await
    }

    /// Send the given message to the connected peer, returns an `Error` if writing to the socket
    /// fails
    #[inline]
    pub(crate) async fn send<R: Request>(&self, ctx: &ContextInternal, msg: &R) -> std::io::Result<()> {
        ctx.socks
            .send(
                &self.conn,
                PacketKind::Message(R::KIND),
                msg,
            )
            .await
    }
}
