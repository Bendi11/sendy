use std::sync::Arc;

use bytes::Bytes;
use futures::Future;
use tokio::sync::oneshot;

use crate::{net::{sock::{ReliableSocketConnection, PacketKind}, msg::{ReceivedMessage, MessageKind}}, req::{Request, Response, StatefulToBytes}, ctx::Context, ser::ToBytes};


/// A connection to a remote peer over UDP
pub struct Peer {
    conn: Arc<ReliableSocketConnection>,
}

/// Structure implementing [ToBytes] that allows stateful conversions to bytes using the
/// [Context]'s cryptography keys
struct ToBytesContext<'a, 'b, T: StatefulToBytes> {
    ctx: &'a Context,
    val: &'b T,
}

impl Peer {
    /// Create a new peer connection using the given socket state
    pub(crate) fn new(conn: ReliableSocketConnection) -> Self {
        Self {
            conn: Arc::new(conn),
        }
    }

    /// Await the reception of a request from the connected peer
    #[inline]
    pub async fn recv(&self) -> ReceivedMessage {
        self.conn.recv().await
    }

    /// Send the given request message and await a response from the remote
    #[inline]
    pub async fn send_wait_response<'a, R: Request>(
        &self,
        ctx: &'a Context,
        msg: &'a R,
    ) -> std::io::Result<impl Future<Output=Bytes> + 'a> {
        ctx.socks.send_wait_response(&self.conn, R::KIND, ToBytesContext { ctx, val: msg }).await
    }

    /// Respond to the given request message with a payload only, no message kind needed
    #[inline]
    pub async fn respond<R: Response>(
        &self,
        ctx: &Context,
        req: &ReceivedMessage,
        response: R,
    ) -> std::io::Result<()> {
        ctx
            .socks
            .send_with_id(
                &self.conn,
                req.id,
                PacketKind::Message(MessageKind::Respond),
                ToBytesContext { ctx, val: &response },
            )
            .await
    }

    /// Send the given message to the connected peer, returns an `Error` if writing to the socket
    /// fails
    #[inline]
    pub async fn send<R: Request>(&self, ctx: &Context, msg: R) -> std::io::Result<()> {
        ctx.socks
            .send(&self.conn, PacketKind::Message(R::KIND), ToBytesContext { ctx, val: &msg })
            .await
    }

}

impl<'a, 'b, T: StatefulToBytes> ToBytes for ToBytesContext<'a, 'b, T> {
   fn write<W: bytes::BufMut>(&self, buf: W) {
       self.val.stateful_write(self.ctx, buf)
   }

    fn size_hint(&self) -> Option<usize> {
        self.val.stateful_size_hint(self.ctx)
    }
}
