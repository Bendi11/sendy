use std::{sync::Arc, num::NonZeroU8};

use bytes::{BytesMut, BufMut, buf::UninitSlice};

use crate::net::msg::Message;

use super::{ReliableSocketInternal, packet::{PacketId, HEADER_SZ, PacketHeader, BLOCK_SIZE, MAX_SAFE_UDP_PAYLOAD, CHECKSUM_OFFSET, BLOCKID_OFFSET}, ToBytes, PacketKind};



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

/// Splits a single [Message]'s bytes into multiple packets preceded by message kind and
/// [transfer](super::packet::PacketKind::Transfer) packet headers
struct MessageSplitter {
    msgid: NonZeroU8,
    blockid: u16,
    bytes_till_split: usize,
    buf: BytesMut,
}

impl MessageSplitter {
    /// Create a new `MessageSplitter` with the given message kind and ID
    pub fn new(kind: PacketKind, msgid: NonZeroU8) -> Self {
        let mut me = Self {
            msgid,
            blockid: 0,
            bytes_till_split: BLOCK_SIZE,
            buf: BytesMut::new()
        };
        
        me.split(kind);
        me
    }
    
    /// Return an iterator over the produced packet bytes
    pub fn into_packet_iter(&mut self) -> impl Iterator<Item = &[u8]> {
        self
            .buf
            .chunks_mut(MAX_SAFE_UDP_PAYLOAD)
            .enumerate()
            .map(|(idx, pkt)| {
                let checksum = crc32fast::hash(&pkt[HEADER_SZ..]);
                (&mut pkt[CHECKSUM_OFFSET..]).put_u32_le(checksum);
                if idx == 0 {
                    (&mut pkt[BLOCKID_OFFSET..]).put_u16_le(self.blockid);
                }
                &pkt[..]
            })
    }

    /// Write a new packet header to the buffer
    fn split(&mut self, kind: PacketKind) {
        let header = PacketHeader {
            kind,
            id: PacketId { msgid: self.msgid, blockid: self.blockid },
            //Checksum is a placeholder until the full packet is written
            checksum: 0,
        };

        self.blockid += 1;
        header.write(&mut self.buf);
    }
}

unsafe impl BufMut for MessageSplitter {
    fn remaining_mut(&self) -> usize { self.buf.remaining_mut() }

    fn chunk_mut<'a>(&'a mut self) -> &'a mut UninitSlice {
        let remaining = self.buf.chunk_mut().len();
        &mut self.buf.chunk_mut()[..self.bytes_till_split.min(remaining)]
    }

    unsafe fn advance_mut(&mut self, mut cnt: usize) {
        while cnt >= self.bytes_till_split {
            println!("split with {} left, advance {}", self.bytes_till_split, cnt);
            self.buf.advance_mut(self.bytes_till_split);
            cnt -= self.bytes_till_split;
            self.split(PacketKind::Transfer);
            self.bytes_till_split = BLOCK_SIZE;
        }

        self.bytes_till_split -= cnt;
        println!("{} left", self.bytes_till_split);

        self.buf.advance_mut(cnt);
    }
}

#[cfg(test)]
mod tests {
    use crate::net::{msg::{TestMessage, MessageKind}, sock::FromBytes};

    use super::*;
    
    #[test]
    fn test_message_splitter() {
        const TEST_LEN: usize = 1000;
        let msgid = NonZeroU8::new(50).unwrap();
        let mut splitter = MessageSplitter::new(PacketKind::Message(MessageKind::Test), msgid);
        let packet = TestMessage((0..TEST_LEN).map(|v| v.to_le_bytes()[0]).collect::<Vec<u8>>());

        packet.write(&mut splitter);

        let packets = splitter.into_packet_iter().collect::<Vec<_>>();
        let blocks = TEST_LEN / BLOCK_SIZE + if TEST_LEN % BLOCK_SIZE != 0 { 1 } else { 0 };
        assert_eq!(
            packets.len(),
            TEST_LEN / BLOCK_SIZE + if TEST_LEN % BLOCK_SIZE != 0 { 1 } else { 0 }
        );
        
        let chk1 = (0..BLOCK_SIZE).map(|v| v.to_le_bytes()[0]).collect::<Vec<u8>>();
        let chk1 = crc32fast::hash(&chk1);
        assert_eq!(
            PacketHeader::parse(packets[0]).unwrap(),
            PacketHeader {
                kind: TestMessage::KIND,
                id: PacketId { msgid, blockid: blocks as u16 },
                checksum: chk1,
            }
        );
    }
}
