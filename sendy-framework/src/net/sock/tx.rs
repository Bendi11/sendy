use std::{sync::{Arc, atomic::{AtomicU8, Ordering, AtomicU32}}, num::NonZeroU8, time::{UNIX_EPOCH, Instant, Duration}};

use bytes::{BytesMut, BufMut, buf::UninitSlice};
use futures::stream::FuturesUnordered;
use tokio::sync::{Semaphore, Notify};

use crate::net::msg::Message;

use super::{ReliableSocketInternal, packet::{PacketId, HEADER_SZ, PacketHeader, BLOCK_SIZE, MAX_SAFE_UDP_PAYLOAD, CHECKSUM_OFFSET, BLOCKID_OFFSET}, ToBytes, PacketKind, FromBytes, SocketConfig};

/// Sensitivity to the RTT measurement to new changes in the response time in 100ths of a ms
pub(crate) const RTT_ESTIMATION_ALPHA: u32 = 50;

/// State needed to limit the number of packets sent at any time, with state needed for
/// transmitting threads to block until a permit is available to send
#[derive(Debug)]
pub(crate) struct ReliableSocketCongestionControl {
    /// Governor determining how many packets may be sent in parallel
    pub permits: Semaphore,
    /// Atomic used to synchronize `permits` amd `window` by making threads that possess a transmit
    /// permit forget their permit instead of returning it to `permits`
    pub permits_to_remove: AtomicU8,
    /// The size of the transmit window - how many packets may be sent and awaiting an ACK packet
    pub window: AtomicU8,
    /// Estimated Round Trip Time of the connection
    pub rtt: AtomicU32,
}

impl ReliableSocketCongestionControl {
    pub fn new(cfg: &SocketConfig) -> Self {
        Self {
            permits: Semaphore::new(cfg.transmission_window_sz as usize),
            permits_to_remove: AtomicU8::new(0),
            window: AtomicU8::new(cfg.transmission_window_sz as u8),
            rtt: AtomicU32::new(200),
        }
    }
}

impl ReliableSocketInternal {
    /// Send a single message via UDP, splitting the message into as many packets as necessary to
    /// transmit
    pub async fn send<M: Message>(&self, id: NonZeroU8, msg: M) -> std::io::Result<()> {
        let mut splitter = MessageSplitter::new(M::KIND, id);
        msg.write(&mut splitter);
        let mut pkts = splitter
            .into_packet_iter()
            .map(|(id, pkt)| self.send_wait_ack(id, pkt));
        
        //Must send the first packet and wait for ack
        match pkts.next() {
            Some(first) => first.await,
            None => {
                log::error!("MessageSplitter did not produce a single packet for message {:?}", M::KIND);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "MessageSplitter produced no packets"
                ));
            }
        }
        
        futures::future::join_all(pkts).await;
        Ok(())
    }
    
    /// Repeatedly send the given packet via UDP while waiting for an ACK packet in response
    async fn send_wait_ack(&self, id: PacketId, pkt: &[u8]) {
        let permit = self.congestion.permits.acquire().await.expect("Transmit permit semaphore closed");
        let wait_ack = Arc::new(Notify::new());
        self.awaiting_ack.insert(id, wait_ack.clone());

        let mut send_time = Instant::now();

        let resend = async {
            loop {
                self.sock.send(pkt).await?;
                send_time = Instant::now();
                tokio::time::sleep(
                    Duration::from_millis(
                        self.cfg.extra_wait_for_ack_ms as u64 +
                        self.congestion.rtt.load(Ordering::SeqCst) as u64
                    )
                ).await;

                tokio::task::yield_now().await;
                let old_window = self.congestion.window.load(Ordering::SeqCst);
                let window = old_window / 2;
                
                if let Ok(_) = self.congestion.window.compare_exchange(old_window, window, Ordering::SeqCst, Ordering::Relaxed) {
                    self.congestion.permits_to_remove.fetch_add(window, Ordering::SeqCst);
                }
            }
        };


        tokio::select! {
            _ = wait_ack.notified() => {
                let to_remove = self.congestion.permits_to_remove.load(Ordering::SeqCst);
                if to_remove > 0 {
                    if let Ok(_) = self.congestion.permits_to_remove.compare_exchange(to_remove, to_remove - 1, Ordering::SeqCst, Ordering::Relaxed) {
                        permit.forget();
                        log::info!("Permit removed");
                    }
                }

                self.congestion.permits.add_permits(1);   
            },
            std::io::Result::<()>::Err(e) = resend => {
                log::error!("I/O error when transmitting {:?}: {}", id, e);
            }
        }
    }

    /// Send the given [Message] - this function performs NO message splitting, so the encoded
    /// size of `msg` MUST be less than BLOCK_SIZE - e.g. the message must
    /// be a control message (see [PacketKind](super::packet::PacketKind))
    pub async fn send_single_raw<M: Message>(&self, id: PacketId, msg: M) -> std::io::Result<()> {
        let permit = self.congestion.permits.acquire().await.expect("Transmit permit semaphore closed");

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

        self.sock.send_to(&buf, self.remote).await?;

        drop(permit);

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
    /// Create a new `MessageSplitter` for the given message kind and ID
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
    
    /// Return an iterator over the produced packet windows, each slice will begin with a packet
    /// header and end with a payload segment between 0 and BLOCK_SIZE bytes long
    pub fn into_packet_iter(&mut self) -> impl Iterator<Item = (PacketId, &[u8])> {
        //Write the number of packets to follow in the first packet's blockid field
        (&mut self.buf[BLOCKID_OFFSET..]).put_u16_le(self.blockid);
        self
            .buf
            .chunks_mut(MAX_SAFE_UDP_PAYLOAD)
            .map(|pkt| {
                let checksum = crc32fast::hash(&pkt[HEADER_SZ..]);
                (&mut pkt[CHECKSUM_OFFSET..]).put_u32_le(checksum);
                let id = PacketId::parse(&pkt[1..]).expect("MessageSplitter produced invalid packet id");
                (id, &pkt[..])
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
            self.buf.advance_mut(self.bytes_till_split);
            self.split(PacketKind::Transfer);
            cnt -= self.bytes_till_split;
            self.bytes_till_split = BLOCK_SIZE;
        }

        self.bytes_till_split -= cnt;

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
        let payload = (0..TEST_LEN).map(|v| v.to_le_bytes()[0]).collect::<Vec<u8>>();
        let mut splitter = MessageSplitter::new(PacketKind::Message(MessageKind::Test), msgid);
        let packet = TestMessage(payload.clone());

        packet.write(&mut splitter);

        let packets = splitter.into_packet_iter().collect::<Vec<_>>();
        let blocks = TEST_LEN / BLOCK_SIZE + if TEST_LEN % BLOCK_SIZE != 0 { 1 } else { 0 };
        assert_eq!(
            packets.len(),
            TEST_LEN / BLOCK_SIZE + if TEST_LEN % BLOCK_SIZE != 0 { 1 } else { 0 }
        );
        
        let chk1 = crc32fast::hash(&payload[..BLOCK_SIZE]);
        assert_eq!(
            PacketHeader::parse(packets[0].1).unwrap(),
            PacketHeader {
                kind: TestMessage::KIND,
                id: PacketId { msgid, blockid: blocks as u16 },
                checksum: chk1,
            }
        );
    }
}
