use std::{time::Duration, net::{SocketAddr, SocketAddrV4, Ipv4Addr}, sync::Arc};

use tokio::{net::UdpSocket, sync::broadcast::{Sender, channel}};

use self::{tx::ReliableSocketTx, recv::ReliableSocketRecvInternal};

use super::packet::AckMessage;

mod recv;
mod tx;

const MAX_IN_TRANSIT_MSG: usize = 5;
const MAX_PACKET_SZ: usize = 500;
const HEADER_SZ: usize = 6;
const BLOCK_SIZE: usize = MAX_PACKET_SZ - HEADER_SZ;
const INVALID_MSG_ID: u8 = 0;
const WAIT_FOR_ACK: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug)]
pub(crate) struct AckNotification {
    pub msgid: u8,
    pub blockid: u32,
}


pub struct ReliableSocket {
    tx: ReliableSocketTx,
    rx: ReliableSocketRecvInternal,
}

impl ReliableSocket {
    pub async fn tunnel_connect(other: SocketAddrV4) -> Result<Self, std::io::Error> {
        let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, other.port())).await?;
        sock.connect(other).await?;

        let sock = Arc::new(sock);

        let (ack_chan, _) = channel::<AckNotification>(MAX_IN_TRANSIT_MSG);
        
        let this = Self {
            tx: ReliableSocketTx::new(ack_chan.clone(), sock.clone()),
            rx: ReliableSocketRecvInternal::new(ack_chan, sock),
        };

        this.tx.send(AckMessage).await?;

        Ok(this)
    }
}
