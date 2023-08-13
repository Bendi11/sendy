use std::net::SocketAddr;

use bytes::Bytes;
use futures::Future;

use crate::{
    ctx::Context,
    model::crypto::{PublicKeychain, SignedCertificate},
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
}

impl Peer {
    /// Disconnect from this peer
    pub async fn disconnect(self, ctx: &Context) -> std::io::Result<()> {
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

    /// Send the given request message and await a response from the remote
    #[inline]
    pub async fn send_wait_response<'a, R: Request>(
        &'a self,
        ctx: &'a Context,
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
    pub async fn respond<R: Response>(
        &self,
        ctx: &Context,
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
    pub async fn send<R: Request>(&self, ctx: &Context, msg: &R) -> std::io::Result<()> {
        ctx.socks
            .send(
                &self.conn,
                PacketKind::Message(R::KIND),
                msg,
            )
            .await
    }
}
