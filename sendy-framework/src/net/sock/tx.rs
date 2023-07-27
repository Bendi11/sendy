use std::sync::Arc;

use bytes::BytesMut;

use crate::net::msg::Message;

use super::{ReliableSocketInternal, packet::{PacketId, HEADER_SZ, PacketHeader}, ToBytes};



impl ReliableSocketInternal {
    /// Send the given [Message] - this function performs NO packet fragmentation, so the encoded
    /// size of `msg` MUST be less than the minimum maximum reassembly size - e.g. the message must
    /// be a control message (see [PacketKind](super::packet::PacketKind))
    pub async fn send_single_raw<M: Message>(self: Arc<Self>, id: PacketId, msg: M) -> std::io::Result<()> {
        let encoded_sz = msg.size_hint();
        //allocate extra space in the packet buffer for the header
        let mut buf = BytesMut::with_capacity(msg.size_hint().unwrap_or(0) + HEADER_SZ);
        
        //Don't waste time writing nothing and calculating the checksum if there is no payload
        let checksum = if encoded_sz == Some(0) {
            0
        } else {
            msg.write(&mut buf[HEADER_SZ..]);
            crc32fast::hash(&buf[HEADER_SZ..])
        };
        
        let header = PacketHeader {
            kind: M::KIND,
            id,
            checksum,
        };

        header.write(&mut buf[..HEADER_SZ]);

        Ok(())
    }
}
