use std::{
    collections::{HashMap, VecDeque},
    io::{ErrorKind, Cursor},
    net::SocketAddr,
    sync::{
        atomic::{AtomicU8, Ordering, AtomicUsize},
        Arc,
    }, time::Duration,
};

use bytes::{Buf, BytesMut, BufMut};
use futures::stream::FuturesUnordered;


use tokio::{
    net::UdpSocket,
    sync::{
        Mutex, Notify, Semaphore,
    }, time::Instant,
};

use crate::net::{packet::{Message, PacketHeader, PacketKind, ToBytes}, sock::{HEADER_SZ, MAX_PACKET_SZ}};

use super::{AckNotification, BLOCK_SIZE, MAX_IN_TRANSIT_BLOCK, MAX_IN_TRANSIT_MSG, WAIT_FOR_ACK};

const RTT_ESTIMATION_ALPHA: f32 = 0.5;

pub(crate) struct ReliableSocketTx {
    ack_chan: Arc<Mutex<HashMap<AckNotification, Arc<Notify>>>>,
    sock: Arc<UdpSocket>,
    id: AtomicU8,
    //With MAX_IN_TRANSIT_MSG permits
    sending_msgs: Semaphore,
    addr: Arc<SocketAddr>,
    choke: Mutex<usize>,
    //RTT in ms
    rtt: AtomicUsize,
    //Total number of dropped packets
    dropped_pkts: AtomicUsize,
}

impl ReliableSocketTx {
    pub(crate) fn new(
        addr: Arc<SocketAddr>,
        ack_chan: Arc<Mutex<HashMap<AckNotification, Arc<Notify>>>>,
        sock: Arc<UdpSocket>,
    ) -> Self {
        Self {
            ack_chan,
            sock,
            id: AtomicU8::new(0),
            sending_msgs: Semaphore::new(MAX_IN_TRANSIT_MSG),
            addr,
            rtt: AtomicUsize::new(500),
            dropped_pkts: AtomicUsize::new(0),
            choke: Mutex::new(MAX_IN_TRANSIT_BLOCK),
        }
    }

    pub(crate) async fn send<M: Message>(&self, msg: M) -> Result<(), std::io::Error> {
        if let Err(e) = self.sending_msgs.acquire().await {
            log::error!("Failed to acquire semaphore permit: {}", e);
            return Err(std::io::Error::new(ErrorKind::Other, e));
        }

        let msgid = self.id.fetch_add(1, Ordering::AcqRel);
        let msgid = if msgid == 0 {
            self.id.fetch_add(1, Ordering::AcqRel)
        } else {
            msgid
        };

        struct MessageWriter(BytesMut);

        impl std::io::Write for MessageWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                for block in buf.chunks(BLOCK_SIZE) {
                    self.0.extend_from_slice(&[0u8 ; HEADER_SZ]);
                    self.0.extend_from_slice(block);
                }

                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        
        let mut buf = MessageWriter(BytesMut::new());
        msg.write(&mut buf)?;
        let mut buf = buf.0;

        let block_count = buf.len() / MAX_PACKET_SZ + if buf.len() % MAX_PACKET_SZ != 0 { 1 } else { 0 };

        let mut chunks = buf.chunks_mut(MAX_PACKET_SZ).enumerate();
        let mut default_header = [0u8 ; HEADER_SZ];
        let (_, first) = chunks.next().unwrap_or((0, &mut default_header));

        let first_pkt = self.send_wait_ack(
            PacketHeader {
                kind: M::TAG,
                msgid,
                blockid: block_count as u32,
                checksum: 0,
            },
            first,
        );

        first_pkt.await?;

        let mut futures = chunks
            .map(|(blockid, block)| Box::pin(self.send_wait_ack(
                    PacketHeader {
                        kind: PacketKind::Transfer,
                        msgid,
                        blockid: blockid as u32,
                        checksum: 0,
                    },
                    block,
                ))
            );

        loop {
            let packets = {
                let choke = self.choke.lock().await;
                let packets = (&mut futures).take(*choke).collect::<FuturesUnordered<_>>();
                if packets.len() < *choke {
                    drop(choke);
                    futures::future::join_all(packets).await;
                    break
                }

                packets
            };
            
            futures::future::join_all(packets).await;
        }

        println!("dropped: {:?} packets, rtt {:?} ms", self.dropped_pkts, self.rtt);
        Ok(())
    }

    async fn send_wait_ack(
        &self,
        mut pkt: PacketHeader,
        buf: &mut [u8],
    ) -> Result<(), std::io::Error> {
        let ack = Arc::new(Notify::new());
        self.ack_chan.lock().await.insert(
            AckNotification { msgid: pkt.msgid, blockid: pkt.blockid },
            ack.clone()
        );
        
        let checksum = crc32fast::hash(&buf[HEADER_SZ..]);
        pkt.checksum = checksum;
        
        let mut buf = buf.writer();
        pkt.write(&mut buf)?;
        let buf = buf.into_inner();


        let send_time = Mutex::new(Instant::now());
        
        #[allow(unreachable_code)]
        let resend = async {
            loop {
                log::trace!("SENT {:?} {}.{}", pkt.kind, pkt.msgid, pkt.blockid);
                self.sock.send_to(&buf, &*self.addr).await?;
                *send_time.lock().await = Instant::now();
                tokio::time::sleep(Duration::from_millis(self.rtt.load(Ordering::Relaxed) as u64) + WAIT_FOR_ACK).await;
                self.dropped_pkts.fetch_add(1, Ordering::SeqCst);

                let mut choke = self.choke.lock().await;
                *choke = (*choke / 2).min(1);
                tokio::task::yield_now().await;
            }

            Result::<(), std::io::Error>::Ok(())
        };

        tokio::select! {
            _ = ack.notified() => {
                let rtt = send_time.lock().await.elapsed().as_millis() as usize;
                let _ = self.rtt.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |v| Some((RTT_ESTIMATION_ALPHA * (v as f32) + (1. - RTT_ESTIMATION_ALPHA) * (rtt as f32)) as usize)
                );
                
                let mut choke = self.choke.lock().await;
                if *choke < MAX_IN_TRANSIT_BLOCK {
                    *choke += 1;
                }
                Ok(())
            },
            Err(e) = resend => {
                log::error!(
                    "Failed to send block {}.{}: {}",
                    pkt.msgid,
                    pkt.blockid,
                    e
                );

                Err(e)
            }
        }
    }
}
