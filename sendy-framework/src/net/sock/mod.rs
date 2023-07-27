mod recv;
mod tx;
mod packet;

use std::time::Duration;

pub(crate) use packet::PacketKind;
pub use packet::{ToBytes, FromBytes};

const MAX_IN_TRANSIT_MSG: usize = 5;
const MAX_IN_TRANSIT_BLOCK: usize = 2;
const MAX_PACKET_SZ: usize = 50_000;
const HEADER_SZ: usize = 10;
const BLOCK_SIZE: usize = MAX_PACKET_SZ - HEADER_SZ;
const WAIT_FOR_ACK: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct AckNotification {
    pub msgid: u8,
    pub blockid: u32,
}
