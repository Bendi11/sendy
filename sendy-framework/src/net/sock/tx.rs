use std::{
    collections::HashMap,
    io::ErrorKind,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
};

use futures::stream::FuturesUnordered;


use tokio::{
    net::UdpSocket,
    sync::{
        Mutex, Notify, Semaphore,
    },
};

use crate::net::packet::{Message, PacketHeader, PacketKind, ToBytes};

use super::{AckNotification, BLOCK_SIZE, MAX_IN_TRANSIT_BLOCK, MAX_IN_TRANSIT_MSG, WAIT_FOR_ACK};

pub(crate) struct ReliableSocketTx {
    ack_chan: Arc<Mutex<HashMap<AckNotification, Arc<Notify>>>>,
    sock: Arc<UdpSocket>,
    id: AtomicU8,
    //With MAX_IN_TRANSIT_MSG permits
    sending_msgs: Semaphore,
    addr: Arc<SocketAddr>,
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

        let send_limit = Arc::new(Semaphore::new(MAX_IN_TRANSIT_BLOCK));

        let first_pkt = {
            let mut chan = self.ack_chan.lock().await;

            let not = Arc::new(Notify::new());
            chan.insert(
                AckNotification {
                    msgid,
                    blockid: block_count as u32,
                },
                not.clone(),
            );

            self.send_wait_ack(
                PacketHeader {
                    kind: M::TAG,
                    msgid,
                    blockid: block_count as u32,
                },
                first,
                send_limit.clone(),
                not,
            )
        };

        first_pkt.await?;

        let futures = {
            let mut chan = self.ack_chan.lock().await;

            chunks
                .map(|(blockid, block)| {
                    let notify_ack = Arc::new(Notify::new());
                    chan.insert(
                        AckNotification {
                            msgid,
                            blockid: blockid as u32,
                        },
                        notify_ack.clone(),
                    );

                    Box::pin(self.send_wait_ack(
                        PacketHeader {
                            kind: PacketKind::Transfer,
                            msgid,
                            blockid: blockid as u32,
                        },
                        block,
                        send_limit.clone(),
                        notify_ack,
                    ))
                })
                .collect::<FuturesUnordered<_>>()
        };

        futures::future::join_all(futures).await;
        Ok(())
    }

    async fn send_wait_ack(
        &self,
        pkt: PacketHeader,
        body: impl ToBytes,
        block: Arc<Semaphore>,
        ack: Arc<Notify>,
    ) -> Result<(), std::io::Error> {
        let mut buf = vec![];
        pkt.write(&mut buf)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?;

        body.write(&mut buf)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?;

        let permit = block.acquire().await;
        
        #[allow(unreachable_code)]
        let resend = async {
            loop {
                log::trace!("SENT {:?} {}.{}", pkt.kind, pkt.msgid, pkt.blockid);
                self.sock.send_to(&buf[..], &*self.addr).await?;
                tokio::time::sleep(WAIT_FOR_ACK).await;
            }

            Result::<(), std::io::Error>::Ok(())
        };

        tokio::select! {
            _ = ack.notified() => {
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
