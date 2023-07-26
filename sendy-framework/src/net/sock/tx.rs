use std::{sync::{Arc, atomic::{AtomicU8, Ordering}}, io::ErrorKind, net::SocketAddr};

use futures::stream::FuturesUnordered;
use tokio::{sync::{broadcast::{Sender, error::RecvError}, Semaphore}, net::UdpSocket};

use crate::net::packet::{Message, ToBytes, PacketHeader, PacketKind};

use super::{AckNotification, BLOCK_SIZE, WAIT_FOR_ACK, MAX_IN_TRANSIT_MSG};


pub(crate) struct ReliableSocketTx {
    ack_chan: Sender<AckNotification>,
    sock: Arc<UdpSocket>,
    id: AtomicU8,
    //With MAX_IN_TRANSIT_MSG permits
    sending_msgs: Semaphore,
    addr: Arc<SocketAddr>,
}


impl ReliableSocketTx {
    pub(crate) fn new(addr: Arc<SocketAddr>, ack_chan: Sender<AckNotification>, sock: Arc<UdpSocket>) -> Self {
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
        let msgid = if msgid == 0 { self.id.fetch_add(1, Ordering::AcqRel) } else { msgid };

        let mut buf = Vec::new();
        msg.write(&mut buf)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;

        let block_count = buf.len() / BLOCK_SIZE + if buf.len() % BLOCK_SIZE != 0 { 1 } else { 0 };

        let mut chunks = buf.chunks(BLOCK_SIZE).enumerate();
        let (_, first) = chunks.next().unwrap_or((0, &[]));
        
        self.send_wait_ack(
            PacketHeader {
                kind: M::TAG,
                msgid,
                blockid: block_count as u32,
            },
            first
        ).await?;

        let futures = chunks
            .map(|(blockid, block)| Box::pin(
                self.send_wait_ack(
                    PacketHeader {
                        kind: PacketKind::Transfer,
                        msgid,
                        blockid: blockid as u32,
                    },
                    block
                )
            ))
            .collect::<FuturesUnordered<_>>();

        let result = futures::future::join_all(futures).await;
        for res in result {
            res?;
        }

        Ok(())
    }

    async fn send_wait_ack(&self, pkt: PacketHeader, body: impl ToBytes) -> Result<(), std::io::Error> {
        let mut buf = vec![];
        pkt.write(&mut buf)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?;

        body.write(&mut buf)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?;

        let resend = async {
            loop {
                log::trace!("SENT");
                self.sock.send_to(&buf[..], &*self.addr).await?;
                tokio::time::sleep(WAIT_FOR_ACK).await;
            }

            Ok::<(), std::io::Error>(())
        };

        let mut ack_chan = self.ack_chan.subscribe();

        let ack = async {
            loop {
                let notification = ack_chan.recv().await?;
                if notification.msgid == pkt.msgid && notification.blockid == pkt.blockid {
                    log::trace!("GOT ACK");
                    break
                }
            }

            Ok::<(), RecvError>(())
        };

        tokio::select! {
            Err(e) = resend => Err(e),
            Ok(()) = ack => {
                log::trace!("Got ACK for {}.{}", pkt.msgid, pkt.blockid);
                Ok(())
            }
        }
    }
}
