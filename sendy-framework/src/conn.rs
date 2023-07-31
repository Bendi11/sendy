use bytes::Bytes;
use tokio::sync::oneshot;

use crate::{net::{sock::{ReliableSocketConnection, PacketKind}, msg::{ReceivedMessage, MessageKind}}, req::{Request, Response, StatefulToBytes}, ctx::Context, ser::ToBytes};


/// A connection to a remote peer over UDP
pub struct Peer {
    internal: ReliableSocketConnection,
}

/// Structure implementing [ToBytes] that allows stateful conversions to bytes using the
/// [Context]'s cryptography keys
struct ToBytesContext<'a, 'b, T: StatefulToBytes> {
    ctx: &'a Context,
    val: &'b T,
}

impl Peer {
    /// Await the reception of a request from the connected peer
    #[inline]
    pub async fn recv(&self) -> ReceivedMessage {
        self.internal.recv().await
    }

    /// Send the given request message and await a response from the remote
    #[inline]
    pub async fn send_wait_response<R: Request>(
        &self,
        ctx: &Context,
        msg: R,
    ) -> std::io::Result<oneshot::Receiver<Bytes>> {
        ctx.socks.send_wait_response(&self.internal, R::KIND, ToBytesContext { ctx, val: &msg }).await
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
                &self.internal,
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
            .send(&self.internal, PacketKind::Message(R::KIND), ToBytesContext { ctx, val: &msg })
            .await
    }

}

impl<'a, 'b, T: StatefulToBytes> ToBytes for ToBytesContext<'a, 'b, T> {
   fn write<W: bytes::BufMut>(&self, buf: W) {
       self.val.write(self.ctx, buf)
   }

    fn size_hint(&self) -> Option<usize> {
        self.val.size_hint(self.ctx)
    }
}
