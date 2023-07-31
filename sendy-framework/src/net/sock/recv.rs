use std::{
    cmp::Ordering,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    num::NonZeroU8,
    sync::{self, atomic::AtomicU16, Arc}, time::Duration,
};

use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use hibitset::AtomicBitSet;
use parking_lot::Mutex;
use slab::Slab;
use tokio::sync::{mpsc::Sender, oneshot, OwnedSemaphorePermit, RwLock, Semaphore};

use crate::{
    net::{
        msg::{MessageKind, ReceivedMessage},
        sock::{
            packet::{PacketHeader, BLOCK_SIZE, HEADER_SZ},
            PacketKind,
        },
    },
    ser::{FromBytes, FromBytesError},
};

use super::{
    packet::{PacketId, MAX_SAFE_UDP_PAYLOAD},
    ReliableSocketInternal, SocketConfig,
};

/// State required for a reliable socket's reception arm
#[derive(Debug)]
pub(crate) struct ReliableSocketRecv {
    /// A map of message IDs from the given IP addresses and message IDs to the channel to send the
    /// message response to when received
    pub responses: DashMap<(IpAddr, NonZeroU8), oneshot::Sender<Bytes>>,
    /// A queue of messages that have finished being received, values here are still tracked by
    /// `buffered_bytes` and should update `buffered_bytes` when removed (this is handled in
    /// [ReliableSocketConnectionInternal](super::ReliableSocketConnectionInternal)
    pub requests: DashMap<IpAddr, Sender<FinishedMessage>>,
    /// A semaphore with [max_recv_mem](crate::net::sock::SocketConfig::max_recv_mem) permits
    /// available, one permit is equal to one byte
    pub recv_buf_permit: Arc<Semaphore>,
    /// Messages that are not yet fully reassembled
    pub messages: RwLock<Slab<RecvMessage>>,
}

/// A fully reassembled message, also containing a permit for the amount of memory it is using
#[derive(Debug)]
pub(crate) struct FinishedMessage {
    /// Semaphore permit acquired from a [ReliableSocketRecv] that should be dropped when the
    /// request is handled
    pub permit: OwnedSemaphorePermit,
    /// The message that was reassembled
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
        Self {
            responses: DashMap::new(),
            requests: DashMap::new(),
            messages: RwLock::new(Slab::with_capacity(8)),
            recv_buf_permit: Arc::new(Semaphore::new(cfg.max_recv_mem)),
        }
    }
}

impl ReliableSocketInternal {
    pub async fn spawn_recv_thread(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::task::spawn(async move {
            loop {
                if self.socks.is_empty() {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue
                }

                let reads = self.socks.iter().map(|sock| {
                    Box::pin(async {
                        if let Err(e) = sock.readable().await {
                            log::error!("Failed to poll socket: {}", e);
                            Err(*sock.key())
                        } else {
                            Ok(sock)
                        }
                    })
                });

                let (readable, ..) = futures::future::select_all(reads).await;
                let readable = match readable {
                    Ok(r) => r,
                    Err(bad_idx) => {
                        drop(readable);
                        self.socks.remove(&bad_idx);
                        continue;
                    }
                };

                let mut buf = [0u8; MAX_SAFE_UDP_PAYLOAD];
                match readable.try_recv_from(&mut buf) {
                    Ok((read, addr)) => {
                        let this = self.clone();
                        this.handle_pkt(addr, read, buf).await;
                    }
                    //False positive - socket is not readable
                    Err(e) if e.kind() == ErrorKind::WouldBlock => (),
                    Err(e) => {
                        log::error!("Failed to receive from UDP socket: {}", e);
                    }
                }
            }
        })
    }
}

impl ReliableSocketInternal {
    /// Create a new buffer in `messages` with enough storage capacity to copy all expected bytes
    /// of the message, waiting to acquire a permit for the expected size of the message
    async fn new_reassemble_buffer(&self, addr: &SocketAddr, id: PacketId, kind: MessageKind) {
        let expected_blocks = id.blockid;
        let size_estimation = expected_blocks as usize * BLOCK_SIZE;
        if size_estimation > self.cfg.max_recv_mem {
            log::error!(
                    "{}: Received message introduction packet that specifies {}B, but only have space for {}B",
                    addr,
                    size_estimation,
                    self.cfg.max_recv_mem,
                );

            return;
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
            msg_id: id.msgid,
            blocks,
            indexes: AtomicBitSet::new(),
            expected_blocks,
            received_blocks: AtomicU16::new(0),
        };

        {
            let mut messages = self.recv.messages.write().await;
            messages.insert(slot);
        }
    }

    /// Handle a packet received via UDP, reassembling the buffer, starting new message receptions,
    /// and sending ACKs when needed
    async fn handle_pkt(
        self: Arc<Self>,
        addr: SocketAddr,
        received_bytes: usize,
        buf: [u8; MAX_SAFE_UDP_PAYLOAD],
    ) {
        let reader = untrusted::Input::from(&buf[0..HEADER_SZ]);
        let header = match reader.read_all(
            FromBytesError::Parsing("Trailing bytes in packet header".to_owned()),
            PacketHeader::parse,
        ) {
            Ok(header) => header,
            Err(e) => {
                log::error!("Failed to parse packet header from {}: {}", addr, e);
                return;
            }
        };

        log::trace!("RECV {:?} {}", header.kind, header.id);
        if header.kind.is_control() {
            if header.kind == PacketKind::Ack {
                if let Some(not) = self.awaiting_ack.get(&header.id) {
                    not.notify_waiters();
                    drop(not);
                    self.awaiting_ack.remove(&header.id);
                }
            } else {
                self.send_ack(&addr, header.id).await;
            }

            return;
        }

        let blockbuf = &buf[HEADER_SZ..received_bytes];
        let checksum = crc32fast::hash(blockbuf);
        if checksum != header.checksum {
            log::warn!(
                "packet {} had invalid checksum {:X} != calculated {:X}",
                header.id,
                header.checksum,
                checksum
            );
            return;
        }

        let blockid = if let PacketKind::Message(kind) = header.kind {
            // We already received the new message packet
            if self
                .recv
                .messages
                .read()
                .await
                .iter()
                .any(|(_, m)| m.msg_id == header.id.msgid)
            {
                self.send_ack(&addr, header.id).await;
                return;
            };

            //No task is waiting for a response message that was sent
            if kind == MessageKind::Respond
                && !self
                    .recv
                    .responses
                    .contains_key(&(addr.ip(), header.id.msgid))
            {
                log::error!(
                    "Received response message for {} but there are no tasks awaiting the response",
                    header.id.msgid,
                );

                self.send_ack(&addr, header.id).await;
                return;
            }

            self.new_reassemble_buffer(&addr, header.id, kind).await;

            0
        } else {
            header.id.blockid
        };

        let messages = self.recv.messages.read().await;
        let (idx, msg) = match messages
            .iter()
            .find(|(_, m)| m.msg_id == header.id.msgid)
            .map(|(idx, msg)| (idx, msg))
        {
            Some((idx, msg)) => (idx, msg),
            None => {
                log::trace!(
                    "{}: Transfer packet received for nonexistent message {}",
                    addr,
                    header.id,
                );

                self.send_ack(&addr, header.id).await;

                return;
            }
        };

        //Already received packet
        if msg.indexes.contains(blockid as u32) {
            self.send_ack(&addr, header.id).await;
            return;
        }

        let block_data_len = received_bytes - HEADER_SZ;

        if block_data_len > 0 {
            msg.blocks[blockid as usize].lock().put_slice(blockbuf);
            msg.indexes.add_atomic(blockid as u32);
            msg.received_blocks
                .fetch_add(1, sync::atomic::Ordering::SeqCst);
        }

        self.send_ack(&addr, header.id).await;

        let received_blocks_count = msg.received_blocks.load(sync::atomic::Ordering::SeqCst);
        match received_blocks_count.cmp(&msg.expected_blocks) {
            Ordering::Equal => {
                drop(messages);
                let mut finished = self.recv.messages.write().await.remove(idx);

                let bytes = if finished.blocks.len() > 0 {
                    let first_block = finished.blocks.swap_remove(0).into_inner();

                    let reassemble =
                        finished
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

                match finished.kind {
                    MessageKind::Respond => {
                        match self.recv.responses.remove(&(addr.ip(), finished.msg_id)) {
                            Some((_, response)) => {
                                if let Err(_) = response.send(bytes) {
                                    log::error!("Failed to send response bytes to listener");
                                }
                            }
                            None => {
                                log::error!(
                                "Received a response for message {} but there are no tasks waiting for it",
                                finished.msg_id,
                            );
                            }
                        }
                    }
                    _ => match self.recv.requests.get(&addr.ip()) {
                        Some(sender) => {
                            if let Err(e) = sender
                                .send(FinishedMessage {
                                    permit: finished.permit,
                                    msg: ReceivedMessage {
                                        kind: finished.kind,
                                        id: finished.msg_id,
                                        bytes,
                                    },
                                })
                                .await
                            {
                                log::error!("Failed to send reassembled message to queue: {}", e);
                            }
                        }
                        None => {
                            log::error!("Finished message from {} but no connection is listening from that address", addr);
                        }
                    },
                }
            }
            Ordering::Greater => {
                log::warn!(
                    "{}: Received {} blocks but expecting only {} - message dropped",
                    addr,
                    received_blocks_count,
                    msg.expected_blocks,
                );
            }
            Ordering::Less => (),
        }
    }

    /// Send an ACK packet to the remote peer, logging any error that occurs when transmitting the
    /// packet
    async fn send_ack(&self, addr: &SocketAddr, id: PacketId) {
        if let Err(e) = self.send_single_raw(addr, id, PacketKind::Ack, ()).await {
            log::error!("{}: Failed to send ACK packet: {}", addr, e,);
        }
    }
}
