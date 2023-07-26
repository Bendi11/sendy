use std::{sync::{Arc, atomic::{AtomicU8, Ordering}}, num::NonZeroU8, pin::Pin, io::ErrorKind};

use futures::{stream::FuturesUnordered, Future};
use hibitset::BitSet;
use tokio::{sync::{broadcast::{Receiver, Sender}, Mutex, Semaphore}, net::UdpSocket};

use crate::net::packet::{Packet, PacketPayload, PacketHeader};

use super::{AckNotification, MAX_IN_TRANSIT_MSG, BLOCK_SIZE};


pub(crate) struct ReliableSocketTx {
    ack_chan: Sender<AckNotification>,
    sock: Arc<UdpSocket>,
    id: AtomicU8,
    //With MAX_IN_TRANSIT_MSG permits
    sending_msgs: Semaphore,
}


impl ReliableSocketTx {
    pub(crate) async fn send<P: Packet>(&self, msg: P) -> Result<(), std::io::Error> {
        if let Err(e) = self.sending_msgs.acquire().await {
            log::error!("Failed to acquire semaphore permit: {}", e);
            return Err(std::io::Error::new(ErrorKind::Other, e));
        }

        let msgid = self.id.fetch_add(1, Ordering::AcqRel);
        let msgid = if msgid == 0 { self.id.fetch_add(1, Ordering::AcqRel) } else { msgid };

        let mut buf = Vec::new();
        msg.write(&mut buf)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;

        let blocks = buf.len() / BLOCK_SIZE + if buf.len() % BLOCK_SIZE != 0 { 1 } else { 0 };

        let mut chunks = buf.chunks(BLOCK_SIZE);
        let first = chunks.next().unwrap();
        

        let futures = buf
            .chunks(BLOCK_SIZE)
            .map(|chunk| Box::pin(async {
                let ack_chan = self.ack_chan.subscribe();

            }));

        Ok(())
    }

    async fn send_wait_ack(&self, pkt: PacketHeader, body: &[u8]) -> Result<(), std::io:Error> {
        
    }
}
