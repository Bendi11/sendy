mod recv;
mod tx;
mod packet;

use std::sync::{atomic::AtomicUsize, Arc};

pub(crate) use packet::PacketKind;
pub use packet::{ToBytes, FromBytes};
use tokio::net::UdpSocket;

/// Configuration options for a socket connection
#[derive(Debug)]
pub struct SocketConfig {
    /// The maximum messages to buffer on the receiving end
    pub max_msg_in_transit: AtomicUsize,
    /// Maximum size of a message in blocks to accept reception of
    pub max_blocks: AtomicUsize,
    /// Transmission window size in packets to start at
    pub transmission_window_sz: AtomicUsize,
    /// Extra time beyond the estimated round trip time to wait for an ACK packet
    pub extra_wait_for_ack_ms: AtomicUsize,
}

/// Wrapper over a UDP socket that is capable of UDP hole punching to connect to another peer, with
/// a minimal reliability layer that guarantees messages are received in the order they are
/// transmitted (unless they dropped for another reason - e.g. the message was too large to accomodate)
pub struct ReliableSocket(Arc<ReliableSocketInternal>);

/// Internal state for the [ReliableSocket], wrapped in an [Arc]
pub(crate) struct ReliableSocketInternal {
    /// The underlying UDP socket to send and receive with
    sock: UdpSocket,
    /// Runtime-configurable options for performance and rate limiting
    cfg: SocketConfig,
}
