mod recv;
mod tx;

const MAX_IN_TRANSIT_MSG: usize = 5;
const MAX_PACKET_SZ: usize = 500;
const HEADER_SZ: usize = 6;
const BLOCK_SIZE: usize = MAX_PACKET_SZ - HEADER_SZ;
const INVALID_MSG_ID: u8 = 0;

struct AckNotification {
    pub msgid: u8,
    pub blockid: u32,
}
