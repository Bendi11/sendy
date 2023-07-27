use std::{
    collections::HashMap,
    io::ErrorKind,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU8, Ordering, AtomicUsize},
        Arc,
    }, time::Duration,
};

use futures::stream::FuturesUnordered;


use tokio::{
    net::UdpSocket,
    sync::{
        Mutex, Notify, Semaphore,
    }, time::Instant,
};

use crate::net::packet::{Message, PacketHeader, PacketKind, ToBytes};

use super::{AckNotification, BLOCK_SIZE, MAX_IN_TRANSIT_BLOCK, MAX_IN_TRANSIT_MSG, WAIT_FOR_ACK};

const RTT_ESTIMATION_ALPHA: f32 = 0.5;

pub(crate) struct ReliableSocketTx {
    ack_chan: Arc<Mutex<HashMap<AckNotification, Arc<Notify>>>>,
    sock: Arc<UdpSocket>,
    id: AtomicU8,
    //With MAX_IN_TRANSIT_MSG permits
    sending_msgs: Semaphore,
    addr: Arc<SocketAddr>,
    //Limits the no. of packets that may be sent, regulated by packet loss
    send_choke: Semaphore,
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
            send_choke: Semaphore::new(MAX_IN_TRANSIT_BLOCK),
            rtt: AtomicUsize::new(500),
            dropped_pkts: AtomicUsize::new(0),
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

        let mut buf = Vec::new();
        msg.write(&mut buf)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;

        let block_count = buf.len() / BLOCK_SIZE + if buf.len() % BLOCK_SIZE != 0 { 1 } else { 0 };

        let mut chunks = buf.chunks(BLOCK_SIZE).enumerate();
        let (_, first) = chunks.next().unwrap_or((0, &[]));

        let first_pkt = self.send_wait_ack(
            PacketHeader {
                kind: M::TAG,
                msgid,
                blockid: block_count as u32,
            },
            first,
        );

        first_pkt.await?;

        let futures = chunks
            .map(|(blockid, block)| Box::pin(self.send_wait_ack(
                    PacketHeader {
                        kind: PacketKind::Transfer,
                        msgid,
                        blockid: blockid as u32,
                    },
                    block,
                ))
            )
            .collect::<FuturesUnordered<_>>();

        futures::future::join_all(futures).await;

        println!("dropped: {:?} packets, rtt {:?} ms", self.dropped_pkts, self.rtt);
        Ok(())
    }

    async fn send_wait_ack(
        &self,
        pkt: PacketHeader,
        body: impl ToBytes,
    ) -> Result<(), std::io::Error> {
        let ack = Arc::new(Notify::new());
        self.ack_chan.lock().await.insert(
            AckNotification { msgid: pkt.msgid, blockid: pkt.blockid },
            ack.clone()
        );

        let mut buf = vec![];
        pkt.write(&mut buf)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?;

        body.write(&mut buf)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?;
        
        let mut permit = self.send_choke.acquire().await.unwrap();

        let send_time = Instant::now();
        
        #[allow(unreachable_code)]
        let resend = async {
            loop {
                log::trace!("SENT {:?} {}.{}", pkt.kind, pkt.msgid, pkt.blockid);
                self.sock.send_to(&buf[..], &*self.addr).await?;
                tokio::time::sleep(Duration::from_millis(self.rtt.load(Ordering::Relaxed) as u64) + WAIT_FOR_ACK).await;
                tokio::task::yield_now().await;
                self.dropped_pkts.fetch_add(1, Ordering::SeqCst);
                let old = std::mem::replace(&mut permit, self.send_choke.acquire().await.unwrap());
                old.forget();
            }

            Result::<(), std::io::Error>::Ok(())
        };

        tokio::select! {
            _ = ack.notified() => {
                let rtt = send_time.elapsed().as_millis() as usize;
                let _ = self.rtt.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |v| Some((RTT_ESTIMATION_ALPHA * (v as f32) + (1. - RTT_ESTIMATION_ALPHA) * (rtt as f32)) as usize)
                );

                drop(permit);
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
