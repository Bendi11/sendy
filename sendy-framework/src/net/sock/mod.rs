mod recv;
mod tx;
mod packet;

use std::{time::Duration, sync::atomic::AtomicUsize};

pub(crate) use packet::PacketKind;
pub use packet::{ToBytes, FromBytes};

const MAX_IN_TRANSIT_BLOCK: usize = 2;
const MAX_PACKET_SZ: usize = 50_000;
const HEADER_SZ: usize = 10;
const BLOCK_SIZE: usize = MAX_PACKET_SZ - HEADER_SZ;
const WAIT_FOR_ACK: Duration = Duration::from_millis(250);

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


