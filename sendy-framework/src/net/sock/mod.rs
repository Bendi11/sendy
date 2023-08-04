mod packet;
mod recv;
mod tx;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::Deref,
    sync::{atomic::AtomicU8, Arc},
};

use dashmap::DashMap;
pub(crate) use packet::PacketKind;
use parking_lot::Mutex;
use tokio::{
    net::UdpSocket,
    sync::{mpsc::Receiver, Notify},
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
    /// Get the address that this socket is connected to
    #[inline]
    pub const fn remote(&self) -> &SocketAddr {
        &self.remote
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

    /// Add a listener for messages on the given port
    pub async fn new_binding(&self, port: u16) -> Result<(), std::io::Error> {
        if !self.internal.socks.contains_key(&port) {
            self.internal.socks.insert(
                port,
                UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).await?,
            );
        }

        Ok(())
    }

    /// Wait for a request to be sent to the host
    pub async fn recv(&self) -> (IpAddr, ReceivedMessage) {
        match self.recv.requests_r.lock().await.recv().await {
            Some(msg) => (msg.0, msg.1.msg),
            None => {
                panic!("Requests channel closed?");
            }
        }
    }

    /// Create a new connection to the given address
    pub async fn connect(&self, addr: SocketAddr) -> std::io::Result<ReliableSocketConnection> {
        self.new_binding(addr.port()).await?;

        Ok(ReliableSocketConnection {
            msgid: AtomicU8::new(1),
            remote: addr,
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
            max_recv_mem: 50_000_000,
            transmission_window_sz: 4,
            extra_wait_for_ack_ms: 250,
        }
    }
}
