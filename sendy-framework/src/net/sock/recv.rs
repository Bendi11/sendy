use std::{cell::OnceCell, sync::{Arc, atomic::AtomicUsize}};

use bytes::BytesMut;
use hibitset::AtomicBitSet;
use tokio::{task::JoinHandle, sync::{Mutex, Semaphore, SemaphorePermit, OwnedSemaphorePermit, mpsc::Receiver, RwLock}};

use crate::net::{sock::{packet::{PacketHeader, HEADER_SZ}, FromBytes, PacketKind}, msg::ReceivedMessage};

use super::{packet::MAX_SAFE_UDP_PAYLOAD, ReliableSocketInternal};


/// State required for a reliable socket's reception arm
pub(crate) struct ReliableSocketRecv {
    /// Background process that handles the reception of packets from the socket
    pub recv_proc: OnceCell<JoinHandle<()>>,
    /// A queue of messages that have finished being received, values here are still tracked by
    /// `buffered_bytes` and should update `buffered_bytes` when removed
    pub finished: Receiver<ReceivedMessage>,
    /// A semaphore with [max_recv_mem](crate::net::sock::SocketConfig::max_recv_mem) permits
    /// available, one permit is equal to one byte
    pub recv_buf_permit: Semaphore,
    /// Messages that are not yet fully reassembled
    pub messages: RwLock<Vec<RecvMessage>>,
}

/// Message that is in the process of reception
pub(crate) struct RecvMessage {
    /// Permit that allows this message to exist
    pub permit: OwnedSemaphorePermit,
    /// Blocks of the file that have been received
    pub blocks: Vec<Mutex<BytesMut>>,
    /// Bitset of all block IDs that have been received successfully
    pub indexes: AtomicBitSet,
    /// Expected length of the message in blocks
    pub expected_blocks: u32,
}


impl ReliableSocketInternal {
    async fn handle_pkt(
        self: Arc<Self>,
        received_bytes: usize,
        buf: [u8; MAX_SAFE_UDP_PAYLOAD],
    ) {
        let header = match PacketHeader::parse(&buf[..]) {
            Ok(header) => header,
            Err(e) => {
                log::error!("Failed to parse packet header from {}: {}", self.remote, e);
                return
            }
        };

        log::trace!("RECV {:?} {}", header.kind, header.id);
        if header.kind.is_control() {
            if header.kind == PacketKind::Ack {
                if let Some(not) = self.awaiting_ack.get(&header.id) {
                    not.notify_waiters();
                    self.awaiting_ack.remove(&header.id);
                }
            } else {
                self.sendack(header.msgid, header.blockid).await;
                //self.finishmsg(header.kind, Vec::new()).await;
            }

            return
        }

        let blockbuf = &buf[HEADER_SZ..received_bytes];
        let checksum = crc32fast::hash(blockbuf);
        if checksum != header.checksum {
            log::warn!("packet {} had invalid checksum {:X} != calculated {:X}", header.id, header.checksum, checksum);
            return
        }

        let (blockid, mut buffer) = match header.kind {
            //Transfer data to existing buffer
            PacketKind::Transfer => (
                header.blockid,
                match recv
                    .iter_mut()
                    .find(|m| m.id.map(|id| id.get() == header.msgid).unwrap_or(false))
                {
                    Some(buf) => buf,
                    None => {
                        log::warn!(
                            "{}: Transfer packet received for nonexistent message {}",
                            self.addr,
                            header.msgid,
                        );

                        self.sendack(header.msgid, header.blockid).await?;

                        return Ok(());
                    }
                },
            ),
            //Beginning a new message
            new_msg => {
                // We already received the new message packet
                if recv
                    .iter()
                    .any(|m| m.id.map(|id| id.get() == header.msgid).unwrap_or(false))
                {
                    self.sendack(header.msgid, header.blockid).await?;
                    return Ok(());
                }

                let open_slot = match recv.iter_mut().find(|m| m.id.is_none()) {
                    Some(slot) => slot,
                    None => {
                        log::error!(
                            "{}: Received new message packet but have no open buffer spaces",
                            self.addr
                        );
                        return Ok(());
                    }
                };

                open_slot.id = Some(match NonZeroU8::new(header.msgid) {
                    Some(id) => id,
                    None => {
                        log::error!(
                            "{}: Received new message packet with invalid message id {}",
                            self.addr,
                            header.msgid,
                        );

                        return Ok(());
                    }
                });
                open_slot.kind = new_msg;
                open_slot.msg_len = header.blockid;
                open_slot.recvd_bytes = 0;
                open_slot.data.clear();
                open_slot
                    .data
                    .extend(std::iter::repeat(0u8).take(header.blockid as usize * BLOCK_SIZE));
                open_slot.recvd_blocks.clear();

                (0, open_slot)
            }
        };

        //Already received packet
        if buffer.recvd_blocks.contains(blockid) {
            self.sendack(header.msgid, header.blockid).await?;
            return Ok(());
        }

        let block_data_len = received_bytes - HEADER_SZ;

        if block_data_len > 0 {
            buffer.recvd_bytes += block_data_len as u32;
            (&mut buffer.data[blockid as usize * BLOCK_SIZE..][..block_data_len])
                .copy_from_slice(blockbuf);
            buffer.recvd_blocks.add(header.blockid);
        }

        self.sendack(header.msgid, header.blockid).await?;

        let recv_block_count = buffer.recvd_blocks.clone().iter().count();
        match recv_block_count.cmp(&(buffer.msg_len as usize)) {
            Ordering::Equal => {
                self.finishmsg(&mut buffer)
                    .await;
                buffer.id = None;
            }
            Ordering::Greater => {
                log::warn!(
                    "{}: Received {} blocks but expecting only {} - message dropped",
                    self.addr, 
                    recv_block_count,
                    buffer.msg_len
                );
                buffer.id = None;
            }
            Ordering::Less => (),
        }

        Ok(())
    }

}

/*const MSG_QUEUE_LEN: usize = 16;

#[derive(Debug)]
pub(crate) struct ReliableSocketRecv {
    handle: JoinHandle<Result<(), std::io::Error>>,
    msg: Mutex<Receiver<(PacketKind, Vec<u8>)>>,
}

impl Drop for ReliableSocketRecv {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[derive(Debug)]
pub(crate) struct ReliableSocketRecvInternal {
    ack_chan: Arc<Mutex<HashMap<AckNotification, Arc<Notify>>>>,
    sock: Arc<UdpSocket>,
    recv: Mutex<[RecvMessage; MAX_IN_TRANSIT_MSG]>,
    msg: Sender<(PacketKind, Vec<u8>)>,
    addr: Arc<SocketAddr>,
}

#[derive(Debug, Clone)]
struct RecvMessage {
    pub id: Option<NonZeroU8>,
    pub data: Vec<u8>,
    pub recvd_blocks: BitSet,
    pub msg_len: u32,
    pub recvd_bytes: u32,
    pub kind: PacketKind,
}

impl Default for RecvMessage {
    fn default() -> Self {
        Self {
            id: None,
            data: vec![],
            recvd_blocks: BitSet::new(),
            msg_len: 0,
            recvd_bytes: 0,
            kind: PacketKind::Ack,
        }
    }
}

impl ReliableSocketRecv {
    pub(crate) fn new(
        addr: Arc<SocketAddr>,
        ack: Arc<Mutex<HashMap<AckNotification, Arc<Notify>>>>,
        sock: Arc<UdpSocket>,
    ) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(MSG_QUEUE_LEN);

        let internal = Arc::new(ReliableSocketRecvInternal::new(addr, ack, sock, tx));
        let handle = tokio::task::spawn(internal.recv());

        Self { handle, msg: rx.into() }
    }

    pub(crate) async fn recv(&self) -> (PacketKind, Vec<u8>) {
        match self.msg.lock().await.recv().await {
            Some(msg) => msg,
            None => {
                log::error!("Channel between recv and main thread closed");
                panic!();
            }
        }
    }
}

impl ReliableSocketRecvInternal {
    pub(crate) fn new(
        addr: Arc<SocketAddr>,
        ack: Arc<Mutex<HashMap<AckNotification, Arc<Notify>>>>,
        sock: Arc<UdpSocket>,
        msg: Sender<(PacketKind, Vec<u8>)>,
    ) -> Self {
        Self {
            ack_chan: ack,
            sock,
            recv: Mutex::new(std::array::from_fn(|_| Default::default())),
            msg,
            addr,
        }
    }

    async fn finishmsg(&self, msg: &mut RecvMessage) {
        let mut vec = std::mem::take(&mut msg.data); 
        vec.truncate(msg.recvd_bytes as usize);
        if let Err(e) = self.msg.send((msg.kind, vec)).await {
            log::error!("Failed to send received message to main thread: {}", e);
        }
    }

    
    pub(crate) async fn recv(self: Arc<Self>) -> Result<(), std::io::Error> {
        loop {
            let mut buf = [0u8; MAX_PACKET_SZ];
            let received_bytes = self.clone().sock.recv(&mut buf).await?;
            tokio::task::spawn(self.clone().handle_pkt(received_bytes, buf));
        }
    }

    async fn sendack(&self, msgid: u8, blockid: u32) -> Result<(), std::io::Error> {
        self.sendraw(&PacketHeader {
            kind: PacketKind::Ack,
            msgid,
            blockid,
            checksum: 0,
        })
        .await
    }

    async fn sendraw<P: ToBytes>(&self, pl: &P) -> Result<(), std::io::Error> {
        let mut buf = Vec::new();
        pl.write(&mut buf)?;
        self.sock.send_to(&buf, &*self.addr).await?;
        Ok(())
    }
}*/
