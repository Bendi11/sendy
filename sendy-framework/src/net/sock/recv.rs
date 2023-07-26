use std::{num::NonZeroU8, collections::{VecDeque, HashSet}, sync::Arc, cmp::Ordering, net::{SocketAddr, Ipv4Addr, SocketAddrV4}};

use hibitset::{BitSet, BitSetLike};
use tokio::{net::UdpSocket, sync::{Mutex, RwLock, Notify}, task::JoinHandle};

use crate::net::packet::FromBytes;

use super::{super::packet::{PacketHeader, ToBytes, PacketKind}, MAX_IN_TRANSIT_MSG, MAX_PACKET_SZ, HEADER_SZ, BLOCK_SIZE, AckNotification};

#[derive(Debug)]
pub(crate) struct ReliableSocketRecv {
    handle: JoinHandle<Result<(), std::io::Error>>,
}

impl Drop for ReliableSocketRecv {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[derive(Debug)]
pub(crate) struct ReliableSocketRecvInternal {
    ack_chan: Arc<RwLock<HashSet<AckNotification>>>,
    ack_wake: Arc<Notify>,
    sock: Arc<UdpSocket>,
    recv: Mutex<[RecvMessage ; MAX_IN_TRANSIT_MSG]>,
    msg: Mutex<VecDeque<(PacketKind, Option<Vec<u8>>)>>,
    addr: Arc<SocketAddr>,
}

#[derive(Debug, Clone)]
struct RecvMessage {
    pub id: Option<NonZeroU8>,
    pub data: Vec<u8>,
    pub recvd_blocks: BitSet,
    pub msg_len: u32,
    pub kind: PacketKind,
}

impl Default for RecvMessage {
    fn default() -> Self {
        Self {
            id: None,
            data: vec![],
            recvd_blocks: BitSet::new(),
            msg_len: 0,
            kind: PacketKind::Ack,
        }
    }
}

impl ReliableSocketRecv {
    pub(crate) fn new(addr: Arc<SocketAddr>, ack_chan: Arc<RwLock<HashSet<AckNotification>>>, ack_wake: Arc<Notify>, sock: Arc<UdpSocket>) -> Self {
        let internal = ReliableSocketRecvInternal::new(addr, ack_chan, ack_wake, sock);
        let handle = tokio::task::spawn(internal.recv());
        Self {
            handle,
        }
    }
}

impl ReliableSocketRecvInternal {
    pub(crate) fn new(addr: Arc<SocketAddr>, ack_chan: Arc<RwLock<HashSet<AckNotification>>>, ack_wake: Arc<Notify>, sock: Arc<UdpSocket>) -> Self {
        Self {
            ack_chan,
            ack_wake,
            sock,
            recv: Mutex::new(std::array::from_fn(|_| Default::default())),
            msg: Mutex::new(VecDeque::new()),
            addr,
        }
    }

    async fn finishmsg(&self, kind: PacketKind, vec: Option<Vec<u8>>) {
        self.msg.lock().await.push_back((kind, vec));
    }

    pub(crate) async fn recv(self) -> Result<(), std::io::Error> {
        let mut buf = [0u8 ; MAX_PACKET_SZ];
        loop {
            let received_bytes = self.sock.recv(&mut buf).await?;
            let header = match PacketHeader::parse(&buf[..]) {
                Ok(header) => header,
                Err(e) => {
                    log::error!("Failed to parse packet header from {}: {}", self.addr, e);
                    continue
                }
            };
            
            log::trace!("RECV {:?} {}.{}", header.kind, header.msgid, header.blockid);
            if header.kind.is_control() {
                if header.kind == PacketKind::Ack {
                    self.ack_chan.write().await.insert(AckNotification {
                        msgid: header.msgid,
                        blockid: header.blockid,
                    });
                    self.ack_wake.notify_waiters();
                    continue
                } else {
                    self.sendack(header.msgid, header.blockid).await?;
                    self.finishmsg(header.kind, None).await;
                    continue
                }
            }

            let mut recv = self.recv.lock().await;
            let (blockid, buffer) = match header.kind {
                //Transfer data to existing buffer
                PacketKind::Transfer => (
                    header.blockid,
                    match recv
                        .iter_mut()
                        .find(|m| m.id.map(|id| id.get() == header.msgid).unwrap_or(false)) {
                        Some(buf) => buf,
                        None => {
                            log::warn!(
                                "{}: Transfer packet received for nonexistent message {}",
                                self.addr,
                                header.msgid,
                            );

                            self.sendack(header.msgid, header.blockid).await?;

                            continue
                        }
                    }
                ),
                //Beginning a new message
                new_msg => {
                    // We already received the new message packet
                    if recv.iter().any(|m| m.id.map(|id| id.get() == header.msgid).unwrap_or(false)) {
                        self.sendack(header.msgid, header.blockid).await?;
                        continue
                    }

                    let open_slot = match recv.iter_mut().find(|m| m.id.is_none()) {
                        Some(slot) => slot,
                        None => {
                            log::error!(
                                "{}: Received new message packet but have no open buffer spaces",
                                self.addr
                            );
                            continue
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

                            continue
                        }
                    });
                    open_slot.kind = new_msg;
                    open_slot.msg_len = header.blockid;
                    open_slot.data.clear();
                    open_slot.data.extend(std::iter::repeat(0u8).take(header.blockid as usize * BLOCK_SIZE));
                    open_slot.recvd_blocks.clear();
                    
                    (0, open_slot)
                }
            };
            
            //Already received packet
            if buffer.recvd_blocks.contains(blockid) {
                self.sendack(header.msgid, header.blockid).await?;
                continue
            }
            
            let block_data_len = received_bytes - HEADER_SZ;

            if block_data_len > 0 {
                (&mut buffer.data[blockid as usize * BLOCK_SIZE..][..block_data_len])
                    .copy_from_slice(&buf[HEADER_SZ..received_bytes]);
                buffer.recvd_blocks.add(header.blockid);
            }

            self.sendack(header.msgid, header.blockid).await?;
            
            let recv_block_count = buffer.recvd_blocks.clone().iter().count();
            match recv_block_count.cmp(&(buffer.msg_len as usize)) {
                Ordering::Equal => {
                    self.finishmsg(buffer.kind, Some(std::mem::take(&mut buffer.data))).await;
                    buffer.id = None;
                },
                Ordering::Greater => {
                    log::warn!(
                        "{}: Received {} blocks but expecting only {} - message dropped",
                        self.sock.peer_addr().unwrap_or(
                            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
                        ),
                        recv_block_count,
                        buffer.msg_len
                    );
                    buffer.id = None;
                },
                Ordering::Less => (),
            }
        }
    }

    async fn sendack(&self, msgid: u8, blockid: u32) -> Result<(), std::io::Error> {
        self.sendraw(&PacketHeader {
            kind: PacketKind::Ack,
            msgid,
            blockid,
        }).await
    }

    async fn sendraw<P: ToBytes>(&self, pl: &P) -> Result<(), std::io::Error> {
        let mut buf = Vec::new();
        pl.write(&mut buf)?;
        self.sock.send_to(&buf, &*self.addr).await?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReliableSocketSendError {

}
