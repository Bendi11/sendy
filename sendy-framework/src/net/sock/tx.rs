use std::{
    num::NonZeroU8,
    sync::{
        atomic::{AtomicU32, AtomicU8, Ordering},
        Arc,
    },
    time::{Duration, Instant}, net::{SocketAddr, IpAddr}, io::ErrorKind,
};

use bytes::{buf::UninitSlice, BufMut, BytesMut, Bytes};
use tokio::{sync::{Notify, Semaphore, oneshot}, net::UdpSocket};

use crate::{
    net::msg::{Request},
    ser::{ToBytes, FromBytes},
};

use super::{
    packet::{
        PacketHeader, PacketId, BLOCKID_OFFSET, BLOCK_SIZE, CHECKSUM_OFFSET, HEADER_SZ,
        MAX_SAFE_UDP_PAYLOAD,
    },
    PacketKind, ReliableSocketInternal, SocketConfig, ReliableSocketConnection,
};

/// Sensitivity to the RTT measurement to new changes in the response time in 10ths of a ms
pub(crate) const RTT_ESTIMATION_ALPHA: u32 = 5;

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

impl ReliableSocketConnection {
    /// Get the next message ID by incrementing the atomic ID counter
    pub fn next_message_id(&self) -> NonZeroU8 {
        //Ensure that the counter rolls over 0
        if let Ok(v) = self
            .msgid
            .compare_exchange(u8::MAX, 1, Ordering::SeqCst, Ordering::Relaxed)
        {
            NonZeroU8::new(v).expect("NoZeroU8 is 0?")
        } else {
            NonZeroU8::new(self.msgid.fetch_add(1, Ordering::SeqCst))
                .expect("msgid counter reached 0")
        }
    }
}

impl ReliableSocketInternal {
    /// Send a message via UDP to the connected peer of `conn`, returning a channel that will send
    /// a value when the peer responds
    pub async fn send_wait_response<R: Request>(&self, conn: &ReliableSocketConnection, req: R) 
        -> std::io::Result<oneshot::Receiver<Bytes>> {
        let msgid = conn.next_message_id();
        let recv = self.wait_response(conn.remote.ip(), msgid);
        self.send_with_id(conn, msgid, PacketKind::Message(R::KIND), req).await?;
        Ok(recv)
    }
    
    /// Send a message to the connected peer via UDP *without* waiting for a response message
    pub async fn send<B: ToBytes>(&self, conn: &ReliableSocketConnection, kind: PacketKind, msg: B) -> std::io::Result<()> {
        let id = conn.next_message_id();
        self.send_with_id(conn, id, kind, msg).await
    }

    /// Send a single message via UDP, splitting the message into as many packets as necessary to
    /// transmit. This method requires a valid message ID to be provided, see [send] for a more
    /// general-purpose method
    pub async fn send_with_id<B: ToBytes>(&self, conn: &ReliableSocketConnection, id: NonZeroU8, kind: PacketKind, msg: B) -> std::io::Result<()> {
        let mut splitter = MessageSplitter::new(kind, id);
        msg.write(&mut splitter);
        let mut pkts = splitter
            .into_packet_iter()
            .map(|(id, pkt)| self.send_wait_ack(conn, id, pkt));

        //Must send the first packet and wait for ack
        match pkts.next() {
            Some(first) => first.await?,
            None => {
                log::error!(
                    "MessageSplitter did not produce a single packet for message {:?}",
                    kind
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "MessageSplitter produced no packets",
                ));
            }
        }

        let results = futures::future::join_all(pkts).await;
        for res in results {
            res?
        }

        Ok(())
    }
    
    /// Wait for the peer to send a response to an already-sent message identified by `msgid`
    fn wait_response(&self, from: IpAddr, msgid: NonZeroU8) -> oneshot::Receiver<Bytes> {
        let (tx, rx) = oneshot::channel::<Bytes>();
        self.recv.responses.insert((from, msgid), tx);
        rx
    }

    /// Send the given [Message] - this function performs NO message splitting, so the encoded
    /// size of `msg` MUST be less than BLOCK_SIZE - e.g. the message must
    /// be a control message (see [PacketKind](super::packet::PacketKind))
    pub async fn send_single_raw<B: ToBytes>(&self, addr: &SocketAddr, id: PacketId, kind: PacketKind, msg: B) -> std::io::Result<()> {
        let encoded_sz = msg.size_hint();
        //allocate extra space in the packet buffer for the header
        let mut buf = BytesMut::with_capacity(msg.size_hint().unwrap_or(0) + HEADER_SZ);

        //Don't waste time writing nothing and calculating the checksum if there is no payload
        let checksum = if encoded_sz == Some(0) {
            0
        } else {
            buf.put_slice(&[0u8; HEADER_SZ]);
            msg.write(&mut buf);
            crc32fast::hash(&buf[HEADER_SZ..])
        };

        let header = PacketHeader {
            kind,
            id,
            checksum,
        };

        header.write(&mut buf[..HEADER_SZ]);
        
        let sock = self.get_sock(addr.port())?;
        sock.send_to(&buf, addr).await?;
        
        Ok(())
    }
    
    /// Repeatedly send the given packet via UDP while waiting for an ACK packet in response
    async fn send_wait_ack(&self, conn: &ReliableSocketConnection, id: PacketId, pkt: &[u8]) -> std::io::Result<()> {
        let permit = conn
            .congestion
            .permits
            .acquire()
            .await
            .expect("Transmit permit semaphore closed");
        let wait_ack = Arc::new(Notify::new());
        self.awaiting_ack.insert(id, wait_ack.clone());

        let mut send_time = Instant::now();
        
        let sock = self.get_sock(conn.remote.port())?;

        let resend = async {
            loop {
                sock.send_to(pkt, conn.remote).await?;
                send_time = Instant::now();
                tokio::time::sleep(Duration::from_millis(
                    self.cfg.extra_wait_for_ack_ms as u64
                        + conn.congestion.rtt.load(Ordering::SeqCst) as u64,
                ))
                .await;

                let old_window = conn.congestion.window.load(Ordering::SeqCst);
                let window = old_window / 2;

                if window > 0 {
                    if let Ok(_) = conn.congestion.window.compare_exchange(
                        old_window,
                        window,
                        Ordering::SeqCst,
                        Ordering::Relaxed,
                    ) {
                        conn.congestion
                            .permits_to_remove
                            .fetch_add(window, Ordering::SeqCst);
                    }
                }
            }
        };

        tokio::select! {
            _ = wait_ack.notified() => {
                let to_remove = conn.congestion.permits_to_remove.load(Ordering::SeqCst);
                if to_remove > 0 {
                    if let Ok(_) = conn.congestion.permits_to_remove.compare_exchange(to_remove, to_remove - 1, Ordering::SeqCst, Ordering::Relaxed) {
                        permit.forget();
                    }
                }

                conn.congestion.window.fetch_add(1, Ordering::SeqCst);
                conn.congestion.permits.add_permits(1);

                let rtt_measure = send_time.elapsed().as_millis() as u32;
                let old_rtt = conn.congestion.rtt.load(Ordering::Relaxed);
                let new_rtt = ((RTT_ESTIMATION_ALPHA * 100) * old_rtt + (10 - RTT_ESTIMATION_ALPHA) * (rtt_measure * 100)) / 1000;
                let _ = conn.congestion.rtt.compare_exchange(old_rtt, new_rtt, Ordering::SeqCst, Ordering::Relaxed);


                Ok(())
            },
            std::io::Result::<()>::Err(e) = resend => {
                log::error!("I/O error when transmitting {:?}: {}", id, e);
                Err(e)
            }
        }
    }

    /// Lookup the socket bound to the given port, or log and return an error
    fn get_sock(&self, port: u16) -> std::io::Result<dashmap::mapref::one::Ref<'_, u16, UdpSocket>> {
        match self.socks.get(&port) {
            Some(sock) => Ok(sock),
            None => {
                log::error!("Attempted to send a packet to an address with which no connection exists: port {}", port);
                return Err(std::io::Error::new(
                    ErrorKind::NotFound,
                    "No connection found"
                ))
            }
        }
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
            buf: BytesMut::new(),
        };

        me.split(kind);
        me
    }

    /// Return an iterator over the produced packet windows, each slice will begin with a packet
    /// header and end with a payload segment between 0 and BLOCK_SIZE bytes long
    pub fn into_packet_iter(&mut self) -> impl Iterator<Item = (PacketId, &[u8])> {
        //Write the number of packets to follow in the first packet's blockid field
        (&mut self.buf[BLOCKID_OFFSET..]).put_u16_le(self.blockid);
        self.buf.chunks_mut(MAX_SAFE_UDP_PAYLOAD).map(|pkt| {
            let checksum = crc32fast::hash(&pkt[HEADER_SZ..]);
            (&mut pkt[CHECKSUM_OFFSET..]).put_u32_le(checksum);
            let id =
                PacketId::parse(&mut untrusted::Reader::new(untrusted::Input::from(&pkt[1..]))).expect("MessageSplitter produced invalid packet id");
            (id, &pkt[..])
        })
    }

    /// Write a new packet header to the buffer
    fn split(&mut self, kind: PacketKind) {
        let header = PacketHeader {
            kind,
            id: PacketId {
                msgid: self.msgid,
                blockid: self.blockid,
            },
            //Checksum is a placeholder until the full packet is written
            checksum: 0,
        };

        self.blockid += 1;
        header.write(&mut self.buf);
    }
}

unsafe impl BufMut for MessageSplitter {
    fn remaining_mut(&self) -> usize {
        self.buf.remaining_mut()
    }

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
    use crate::net::msg::{TestMessage, MessageKind};

    use super::*;

    #[test]
    fn test_message_splitter() {
        const TEST_LEN: usize = 1000;
        let msgid = NonZeroU8::new(50).unwrap();
        let payload = (0..TEST_LEN)
            .map(|v| v.to_le_bytes()[0])
            .collect::<Vec<u8>>();
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
            PacketHeader::parse(
                &mut untrusted::Reader::new(untrusted::Input::from(&packets[0].1))
            ).unwrap(),
            PacketHeader {
                kind: PacketKind::Message(TestMessage::KIND),
                id: PacketId {
                    msgid,
                    blockid: blocks as u16
                },
                checksum: chk1,
            }
        );
    }
}
