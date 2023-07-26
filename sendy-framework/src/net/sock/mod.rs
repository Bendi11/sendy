use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use hibitset::BitSet;
use tokio::{
    net::UdpSocket,
    sync::{
        broadcast::{channel, Sender},
        mpsc::unbounded_channel,
        Mutex, Notify, RwLock,
    },
};

use self::{
    recv::{ReliableSocketRecv, ReliableSocketRecvInternal},
    tx::ReliableSocketTx,
};

use super::packet::{ConnMessage, TestMessage};

mod recv;
mod tx;

const MAX_IN_TRANSIT_MSG: usize = 5;
const MAX_IN_TRANSIT_BLOCK: usize = 5000;
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

        let ack = Arc::new(Mutex::new(HashMap::new()));

        let this = Self {
            tx: ReliableSocketTx::new(addr.clone(), ack.clone(), sock.clone()),
            rx: ReliableSocketRecv::new(addr.clone(), ack, sock),
        };

        this.tx.send(ConnMessage).await?;
        this.tx
            .send(TestMessage {
                buf: vec![100u8; 10_000_000],
            })
            .await?;

        //tokio::time::sleep(Duration::from_secs(10)).await;

        Ok(this)
    }
}
