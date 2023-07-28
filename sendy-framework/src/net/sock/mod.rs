mod recv;
mod tx;
mod packet;

use std::{sync::{atomic::AtomicUsize, Arc}, net::SocketAddr};

use dashmap::DashMap;
pub(crate) use packet::PacketKind;
pub use packet::{ToBytes, FromBytes};
use tokio::{net::UdpSocket, sync::Notify};

use self::{tx::ReliableSocketCongestionControl, packet::PacketId};

/// Configuration options for a socket connection
#[derive(Debug)]
pub struct SocketConfig {
    /// The maximum messages to buffer on the receiving end
    pub max_msg_in_transit: usize,
    /// Maximum bytes of memory to use when buffering received packets
    pub max_recv_mem: usize,
    /// Transmission window size in packets to start at
    pub transmission_window_sz: usize,
    /// Extra time beyond the estimated round trip time to wait for an ACK packet
    pub extra_wait_for_ack_ms: usize,
}

/// Wrapper over a UDP socket that is capable of UDP hole punching to connect to another peer, with
/// a minimal reliability layer that guarantees messages are received in the order they are
/// transmitted (unless they dropped for another reason - e.g. the message was too large to accomodate)
#[derive(Clone, Debug)]
pub struct ReliableSocket(Arc<ReliableSocketInternal>);

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
}
