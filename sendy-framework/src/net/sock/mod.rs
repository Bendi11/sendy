use std::{time::Duration, net::{SocketAddr, SocketAddrV4, Ipv4Addr}, sync::Arc, collections::HashSet};

use hibitset::BitSet;
use tokio::{net::UdpSocket, sync::{broadcast::{Sender, channel}, mpsc::unbounded_channel, RwLock, Notify}};

use self::{tx::ReliableSocketTx, recv::{ReliableSocketRecvInternal, ReliableSocketRecv}};

use super::packet::{ConnMessage, TestMessage};

mod recv;
mod tx;

const MAX_IN_TRANSIT_MSG: usize = 5;
const MAX_IN_TRANSIT_BLOCK: usize = 10;
const MAX_PACKET_SZ: usize = 500;
const HEADER_SZ: usize = 6;
const BLOCK_SIZE: usize = MAX_PACKET_SZ - HEADER_SZ;
const INVALID_MSG_ID: u8 = 0;
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
        
        let bits = Arc::new(RwLock::new(HashSet::new()));
        let waker = Arc::new(Notify::new());

        let this = Self {
            tx: ReliableSocketTx::new(addr.clone(), bits.clone(), waker.clone(), sock.clone()),
            rx: ReliableSocketRecv::new(addr.clone(), bits, waker, sock),
        };

        this.tx.send(ConnMessage).await?;
        this.tx.send(TestMessage { buf: vec![100u8 ; 10_000_000] }).await?;

        tokio::time::sleep(Duration::from_secs(10)).await;

        Ok(this)
    }
}
