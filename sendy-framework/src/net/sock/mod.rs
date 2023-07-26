use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use tokio::{
    net::UdpSocket,
    sync::Mutex,
};

use self::{
    recv::ReliableSocketRecv,
    tx::ReliableSocketTx,
};

use super::packet::{ConnMessage, Message, PacketKind};

mod recv;
mod tx;

const MAX_IN_TRANSIT_MSG: usize = 5;
const MAX_IN_TRANSIT_BLOCK: usize = 255;
const MAX_PACKET_SZ: usize = 500;
const HEADER_SZ: usize = 6;
const BLOCK_SIZE: usize = MAX_PACKET_SZ - HEADER_SZ;
const WAIT_FOR_ACK: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct AckNotification {
    pub msgid: u8,
    pub blockid: u32,
}

pub struct ReliableSocket {
    tx: ReliableSocketTx,
    rx: ReliableSocketRecv,
}

impl ReliableSocket {
    pub async fn tunnel_connect(other: SocketAddrV4) -> Result<Self, std::io::Error> {
        let addr = Arc::new(SocketAddr::V4(other));
        let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, other.port())).await?;

        let sock = Arc::new(sock);

        let ack = Arc::new(Mutex::new(HashMap::new()));

        let this = Self {
            tx: ReliableSocketTx::new(addr.clone(), ack.clone(), sock.clone()),
            rx: ReliableSocketRecv::new(addr.clone(), ack, sock),
        };

        this.tx.send(ConnMessage).await?;

        Ok(this)
    }

    #[inline(always)]
    pub async fn send<M: Message>(&self, msg: M) -> Result<(), std::io::Error> { self.tx.send(msg).await }
    #[inline(always)]
    pub async fn recv(&self) -> (PacketKind, Vec<u8>) { self.rx.recv().await }
}
