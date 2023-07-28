mod recv;
mod tx;
mod packet;

use std::{sync::{atomic::AtomicUsize, Arc}, net::{SocketAddr, SocketAddrV4, Ipv4Addr}};

use dashmap::DashMap;
pub(crate) use packet::PacketKind;
pub use packet::{ToBytes, FromBytes};
use tokio::{net::UdpSocket, sync::Notify};

use self::{tx::ReliableSocketCongestionControl, packet::PacketId, recv::ReliableSocketRecv};

/// Configuration options for a socket connection
#[derive(Debug)]
pub struct SocketConfig {
    /// The maximum messages to buffer on the receiving end
    pub max_msg_in_transit: usize,
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
pub struct ReliableSocket {
    internal: Arc<ReliableSocketInternal>,
    recvproc: tokio::task::JoinHandle<()>,
}

/// Internal state for the [ReliableSocket], wrapped in an [Arc]
#[derive(Debug)]
pub(crate) struct ReliableSocketInternal {
    /// The underlying UDP socket to send and receive with
    sock: UdpSocket,
    /// Address of the peer that this socket is connected to
    remote: SocketAddr,
    /// Runtime-configurable options for performance and rate limiting
    cfg: SocketConfig,
    /// Map of currently-sent packet to their ack wakers
    awaiting_ack: DashMap<PacketId, Arc<Notify>>,
    /// State governing the congestion control algorithm
    congestion: ReliableSocketCongestionControl,
    /// Receiving arm of this socket
    recv: ReliableSocketRecv,
}

impl ReliableSocket {
    /// Create a new socket that is not connected to any remote peer
    pub async fn new(cfg: SocketConfig, port: u16) -> std::io::Result<Self> {
        let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).await?;
        let remote = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
        let congestion = ReliableSocketCongestionControl::new(&cfg);
        let recv = ReliableSocketRecv::new(&cfg);

        let internal = Arc::new(ReliableSocketInternal {
            sock,
            remote,
            cfg,
            awaiting_ack: DashMap::new(),
            congestion,
            recv,
        });

        let recvproc = internal.clone().spawn_recv_thread().await;

        Ok(Self {
            internal,
            recvproc,
        })
    }
}
