mod packet;
mod recv;
mod tx;

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{atomic::AtomicU8, Arc}, ops::Deref,
};

use dashmap::DashMap;
pub(crate) use packet::PacketKind;
use parking_lot::Mutex;
use tokio::{
    net::UdpSocket,
    sync::{mpsc::Receiver, oneshot, Notify},
};

use self::{
    packet::PacketId,
    recv::{FinishedMessage, ReliableSocketRecv},
    tx::ReliableSocketCongestionControl,
};

use super::msg::ReceivedMessage;

/// Configuration options for a socket connection
#[derive(Debug)]
pub struct SocketConfig {
    /// Maximum bytes of memory to use when buffering received packets
    pub max_recv_mem: usize,
    /// Transmission window size in packets to start at
    pub transmission_window_sz: u8,
    /// Extra time beyond the estimated round trip time to wait for an ACK packet
    pub extra_wait_for_ack_ms: usize,
}

/// Wrapper over a UDP socket that is capable of UDP hole punching to connect to another peer, with
/// a minimal reliability layer that guarantees messages are received in the order they are
/// transmitted (unless they dropped for another reason - e.g. the message was too large to accomodate)
#[derive(Debug)]
pub(crate) struct ReliableSocket {
    internal: Arc<ReliableSocketInternal>,
    recvproc: tokio::task::JoinHandle<()>,
}

/// State maintained for each connection to a remote peer, created by a [ReliableSocket]
#[derive(Debug)]
pub(crate) struct ReliableSocketConnection {
    /// Address and port of the remote peer
    remote: SocketAddr,
    /// Counter used to create IDs for transmitted messages
    msgid: AtomicU8,
    /// Channel that fully reassembled messages are sent to
    recv: Mutex<Receiver<FinishedMessage>>,
    /// Congestion control to limit the number of messages that may be sent
    congestion: ReliableSocketCongestionControl,
}

/// Internal state for the [ReliableSocket], wrapped in an [Arc]
#[derive(Debug)]
pub(crate) struct ReliableSocketInternal {
    /// Map of ports to sockets that have been bound to them
    socks: DashMap<u16, UdpSocket>,
    /// Runtime-configurable options for performance and rate limiting
    cfg: SocketConfig,
    /// Map of currently sent packets to their ack wakers
    awaiting_ack: DashMap<PacketId, Arc<Notify>>,
    /// Receiving arm of this socket
    recv: ReliableSocketRecv,
}

impl ReliableSocketConnection {
    /// Await the next message being fully reassembled
    pub async fn recv(&self) -> ReceivedMessage {
        if let Some(next) = self.recv.lock().recv().await {
            //Return the permit tracking buffer space used
            drop(next.permit);
            next.msg
        } else {
            panic!("Message receiver channel closed");
        }
    }
}

impl ReliableSocket {
    /// Create a new socket that is not connected to any remote peer
    pub async fn new(cfg: SocketConfig) -> Self {
        let recv = ReliableSocketRecv::new(&cfg);

        let internal = Arc::new(ReliableSocketInternal {
            socks: DashMap::new(),
            cfg,
            awaiting_ack: DashMap::new(),
            recv,
        });

        let recvproc = internal.clone().spawn_recv_thread().await;

        Self { internal, recvproc }
    }

    /// Create a new connection to the given address
    pub async fn connect(&self, addr: SocketAddr) -> std::io::Result<ReliableSocketConnection> {
        let (sender, recv) = tokio::sync::mpsc::channel(16);
        let recv = Mutex::new(recv);

        self.internal.recv.requests.insert(addr.ip(), sender);

        if !self.internal.socks.contains_key(&addr.port()) {
            self.internal.socks.insert(
                addr.port(),
                UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, addr.port())).await?,
            );
        }

        Ok(ReliableSocketConnection {
            msgid: AtomicU8::new(1),
            remote: addr,
            recv,
            congestion: ReliableSocketCongestionControl::new(&self.internal.cfg),
        })
    }
}

impl AsRef<ReliableSocketInternal> for ReliableSocket {
    fn as_ref(&self) -> &ReliableSocketInternal {
        &self.internal
    }
}

impl Deref for ReliableSocket {
    type Target = ReliableSocketInternal;

    fn deref(&self) -> &Self::Target {
        &self.internal
    }
}

impl Drop for ReliableSocket {
    fn drop(&mut self) {
        self.recvproc.abort();
    }
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            max_recv_mem: 20_000_000,
            transmission_window_sz: 4,
            extra_wait_for_ack_ms: 250,
        }
    }
}
