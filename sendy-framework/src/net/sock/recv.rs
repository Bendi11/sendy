use std::{cell::OnceCell, num::NonZeroU8, sync::{Arc, atomic::AtomicU16, self}, cmp::Ordering};

use bytes::{BytesMut, BufMut, Bytes};
use futures::AsyncReadExt;
use hibitset::{AtomicBitSet, BitSetLike};
use tokio::{task::JoinHandle, sync::{Mutex, Semaphore, OwnedSemaphorePermit, mpsc::{Receiver, Sender, self}, RwLock}};

use crate::net::{sock::{packet::{PacketHeader, HEADER_SZ, BLOCK_SIZE}, FromBytes, PacketKind}, msg::{ReceivedMessage, MessageKind}};

use super::{packet::{MAX_SAFE_UDP_PAYLOAD, PacketId, AckMessage}, ReliableSocketInternal, SocketConfig};


/// State required for a reliable socket's reception arm
#[derive(Debug)]
pub(crate) struct ReliableSocketRecv {
    /// A queue of messages that have finished being received, values here are still tracked by
    /// `buffered_bytes` and should update `buffered_bytes` when removed
    pub finished: Mutex<Receiver<FinishedMessage>>,
    /// Sender to transmit reassembled message buffers back to the main thread
    pub txfinish: Sender<FinishedMessage>,
    /// A semaphore with [max_recv_mem](crate::net::sock::SocketConfig::max_recv_mem) permits
    /// available, one permit is equal to one byte
    pub recv_buf_permit: Arc<Semaphore>,
    /// Messages that are not yet fully reassembled
    pub messages: RwLock<Vec<RecvMessage>>,
}

/// A fully reassembled message, also containing a permit for the amount of memory it is using
#[derive(Debug)]
pub(crate) struct FinishedMessage {
    pub permit: OwnedSemaphorePermit,
    pub msg: ReceivedMessage,
}

/// Message that is in the process of reception
#[derive(Debug)]
pub(crate) struct RecvMessage {
    /// Permit that allows this message to use the amount of bytes it has allocated
    pub permit: OwnedSemaphorePermit,
    /// The type of packet that introduced this message
    pub kind: MessageKind,
    /// Message ID that was transmitted
    pub msg_id: NonZeroU8,
    /// Blocks of the file that have been received
    pub blocks: Vec<Mutex<BytesMut>>,
    /// Bitset of all block IDs that have been received successfully
    pub indexes: AtomicBitSet,
    /// Expected length of the message in blocks
    pub expected_blocks: u16,
    /// Received block count
    pub received_blocks: AtomicU16,
}

impl ReliableSocketRecv {
    /// Create and initialize all state needed to receive messages
    ///
    /// See also: [spawn_recv_thread](ReliableSocketInternal::spawn_recv_thread)
    pub fn new(cfg: &SocketConfig) -> Self {
        let (txfinish, finished) = mpsc::channel(16);

        Self {
            finished: Mutex::new(finished),
            txfinish,
            messages: RwLock::new(Vec::with_capacity(8)),
            recv_buf_permit: Arc::new(Semaphore::new(cfg.max_recv_mem)),
        }
    }
}

impl ReliableSocketInternal {
    pub async fn spawn_recv_thread(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::task::spawn(async move {
            loop {
                let mut buf = [0u8 ; MAX_SAFE_UDP_PAYLOAD];
                match self.sock.recv(&mut buf).await {
                    Ok(read) => {
                        let this = self.clone();
                        tokio::task::spawn(this.handle_pkt(read, buf));
                    },
                    Err(e) => {
                        log::error!("Failed to receive from UDP socket: {}", e);
                    }
                }
            }
        })
    }
}

impl ReliableSocketInternal {
    /// Wait for a message to be fully reassembled and sent from the receiver threat
    pub async fn recv(&self) -> ReceivedMessage {
        if let Some(next) = self.recv.finished.lock().await.recv().await {
            //Return the permit tracking buffer space used
            drop(next.permit);
            next.msg
        } else {
            panic!("Message receiver channel closed");
        }
    }
    
    /// Handle a packet received via UDP, reassembling the buffer, starting new message receptions,
    /// and sending ACKs when needed
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
                self.send_ack(header.id).await;
            }

            return
        }

        let blockbuf = &buf[HEADER_SZ..received_bytes];
        let checksum = crc32fast::hash(blockbuf);
        if checksum != header.checksum {
            log::warn!("packet {} had invalid checksum {:X} != calculated {:X}", header.id, header.checksum, checksum);
            return
        }

        //Modify the blockid if the packet begins a new message
        let true_blockid = if let PacketKind::Message(kind) = header.kind {
            // We already received the new message packet
            if 
                self
                .recv
                .messages
                .read()
                .await
                .iter()
                .any(|m| m.msg_id == header.id.msgid)
            {
                self.send_ack(header.id).await;
                return
            }

            let expected_blocks = header.id.blockid;
            let size_estimation = expected_blocks as usize * BLOCK_SIZE;
            if size_estimation > self.cfg.max_recv_mem {
                log::error!(
                    "{}: Received message introduction packet that specifies {}B, but only have space for {}B",
                    self.remote,
                    size_estimation,
                    self.cfg.max_recv_mem,
                );

                return
            }

            let permit = self
                .recv
                .recv_buf_permit
                .clone()
                .acquire_many_owned(size_estimation as u32)
                .await
                .expect("Receive permits semaphore closed");
            
            //Fill a Vec with contiguous chunks of a buffer that can be individually locked
            let mut blocks = Vec::with_capacity(expected_blocks as usize);
            let mut tmp_buf = BytesMut::with_capacity(size_estimation);
            for _ in 0..expected_blocks {
                let rest = tmp_buf.split_off(BLOCK_SIZE);
                blocks.push(Mutex::new(tmp_buf));
                tmp_buf = rest;
            }

            let slot = RecvMessage {
                permit,
                kind,
                msg_id: header.id.msgid,
                blocks,
                indexes: AtomicBitSet::new(),
                expected_blocks,
                received_blocks: AtomicU16::new(0),
            };
            
            let mut messages = self.recv.messages.write().await;
            messages.push(slot);
            
            0
        } else {
            header.id.blockid
        };
        
        let messages = self.recv.messages.read().await;
        let (idx, msg, mut buffer) = match messages
            .iter()
            .enumerate()
            .find(|(_, m)| m.msg_id == header.id.msgid)
        {
            Some((idx, msg)) => {
                if true_blockid < msg.expected_blocks {
                    (idx, msg, msg.blocks[true_blockid as usize].lock().await)
                } else {
                    log::error!(
                        "{}: Received packet with {} with block id out of range of expected {}",
                        self.remote,
                        header.id,
                        msg.expected_blocks,
                    );
                    
                    return
                }
            },
            None => {
                log::warn!(
                    "{}: Transfer packet received for nonexistent message {}",
                    self.remote,
                    header.id,
                );

                self.send_ack(header.id).await;

                return
            }
        };

        //Already received packet
        if msg.indexes.contains(true_blockid as u32) {
            self.send_ack(header.id).await;
            return
        }

        let block_data_len = received_bytes - HEADER_SZ;

        if block_data_len > 0 {
            buffer.put_slice(blockbuf);
            msg.indexes.add_atomic(true_blockid as u32);
            msg.received_blocks.fetch_add(1, sync::atomic::Ordering::SeqCst);
        }

        self.send_ack(header.id).await;
        
        let received_blocks_count = msg.received_blocks.load(sync::atomic::Ordering::SeqCst);
        match received_blocks_count.cmp(&msg.expected_blocks) {
            Ordering::Equal => {
                let mut finished = self.recv.messages.write().await.swap_remove(idx);

                let bytes = if finished.blocks.len() > 0 {
                    let first_block = finished.blocks.swap_remove(0).into_inner();

                    let reassemble = finished
                        .blocks
                        .into_iter()
                        .fold(first_block, |mut acc, block| {
                            acc.unsplit(block.into_inner());
                            acc
                        });

                    reassemble.freeze()
                } else {
                    Bytes::new()
                };
                
                let _ = self.recv.txfinish.send(FinishedMessage {
                    permit: finished.permit,
                    msg: ReceivedMessage {
                        kind: finished.kind,
                        bytes,
                    }
                }).await;
            }
            Ordering::Greater => {
                log::warn!(
                    "{}: Received {} blocks but expecting only {} - message dropped",
                    self.remote, 
                    received_blocks_count,
                    msg.expected_blocks,
                );
            }
            Ordering::Less => (),
        }
    }
        
    /// Send an ACK packet to the remote peer, logging any error that occurs when transmitting the
    /// packet
    async fn send_ack(&self, id: PacketId) {
        if let Err(e) = self.send_single_raw(id, AckMessage).await {
            log::error!(
                "{}: Failed to send ACK packet: {}",
                self.remote,
                e,
            );
        }
    }
}
