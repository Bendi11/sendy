use std::{io::{Cursor, Read}, num::NonZeroU8, collections::{HashSet, VecDeque}, sync::Arc, cmp::Ordering, net::{SocketAddr, IpAddr, Ipv4Addr, SocketAddrV4}};

use hibitset::{BitSet, BitSetLike};
use tokio::{net::UdpSocket, sync::{Mutex, mpsc::Sender}};

use super::{super::packet::{PacketHeader, PacketPayload, PacketKind, PacketHeaderParseError, Packet}, MAX_IN_TRANSIT_MSG, MAX_PACKET_SZ, HEADER_SZ, BLOCK_SIZE, INVALID_MSG_ID};




/// Minimal reliability layer over a UDP connection
#[derive(Debug)]
struct ReliableSocket {
    sock: UdpSocket,
    recv: Mutex<[RecvMessage ; MAX_IN_TRANSIT_MSG]>,
}

struct AckNotification {
    pub msgid: u8,
    pub blockid: u32,
}

#[derive(Debug)]
struct ReliableSocketRecv {
    ack_chan: Sender<AckNotification>,
    sock: Arc<UdpSocket>,
    recv: Mutex<[RecvMessage ; MAX_IN_TRANSIT_MSG]>,
    msg: Mutex<VecDeque<(PacketKind, Option<Vec<u8>>)>>,
}

#[derive(Debug)]
struct RecvMessage {
    pub id: Option<NonZeroU8>,
    pub data: Vec<u8>,
    pub recvd_blocks: BitSet,
    pub msg_len: u32,
    pub kind: PacketKind,
}

impl ReliableSocketRecv {
    async fn finishmsg(&self, kind: PacketKind, vec: Option<Vec<u8>>) {
        self.msg.lock().await.push_back((kind, vec));
    }

    pub async fn recv(&self) -> Result<(), std::io::Error> {
        let mut buf = [0u8 ; MAX_PACKET_SZ];
        let ip = self.sock.peer_addr().unwrap_or(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        );
        loop {
            let received_bytes = self.sock.recv(&mut buf).await.unwrap();
            let header = PacketHeader::parse(&buf[..]).unwrap();

            if header.kind.is_control() {
                self.sendack(header.msgid, 0).await?;
                self.finishmsg(header.kind, None).await;
            }

            let mut recv = self.recv.lock().await;
            let (blockid, buffer) = match header.kind {
                //Transfer data to existing buffer
                PacketKind::Transfer => (
                    header.msgoff,
                    match recv
                        .iter_mut()
                        .find(|m| m.id.map(|id| id.get() == header.msgid).unwrap_or(false)) {
                        Some(buf) => buf,
                        None => {
                            log::warn!(
                                "{}: Transfer packet received for nonexistent message {}",
                                ip,
                                header.msgid,
                            );
                            continue
                        }
                    }
                ),
                //Beginning a new message
                new_msg => {
                    // We already received the new message packet
                    if recv.iter().any(|m| m.id.map(|id| id.get() == header.msgid).unwrap_or(false)) {
                        self.sendack(header.msgid, 0).await?;
                        continue
                    }

                    let open_slot = match recv.iter_mut().find(|m| m.id.is_none()) {
                        Some(slot) => slot,
                        None => {
                            log::error!(
                                "{}: Received new message packet but have no open buffer spaces",
                                ip
                            );
                            continue
                        }
                    };

                    open_slot.id = Some(match NonZeroU8::new(header.msgid) {
                        Some(id) => id,
                        None => {
                            log::error!(
                                "{}: Received new message packet with invalid message id {}",
                                ip,
                                header.msgid,
                            );
                            continue
                        }
                    });
                    open_slot.kind = new_msg;
                    open_slot.msg_len = header.msgoff;
                    open_slot.data.extend(std::iter::repeat(0u8).take(header.msgoff as usize * BLOCK_SIZE));
                    open_slot.recvd_blocks.clear();
                    
                    (0, open_slot)
                }
            };
            
            //Already received packet
            if buffer.recvd_blocks.contains(blockid) {
                self.sendack(header.msgid, blockid).await?;
                continue
            }
            
            let block_data_len = received_bytes - HEADER_SZ;
            (&mut buffer.data[blockid as usize * BLOCK_SIZE..][..block_data_len]).copy_from_slice(&buf[HEADER_SZ..]);
            buffer.recvd_blocks.add(header.msgoff);

            self.sendack(header.msgid, blockid).await?;
            
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
            msgoff: blockid,
        }).await
    }

    async fn sendraw<P: PacketPayload>(&self, pl: &P) -> Result<(), std::io::Error> {
        let mut buf = Vec::new();
        pl.write(&mut buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.sock.send(&buf).await?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReliableSocketRecvError {
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Failed to parse packet header")]
    PacketHeader(#[from] PacketHeaderParseError),
    #[error("Transfer packet received with nonexistent message ID {0}")]
    TransferMessageId(u8),
    #[error("Sender exceeded the maximum in-transit messages limit of {}", MAX_IN_TRANSIT_MSG)]
    NoOpenSlot,
    #[error("New message packet received with invalid message ID {}", INVALID_MSG_ID)]
    InvalidMsgId,
}

#[derive(Debug, thiserror::Error)]
pub enum ReliableSocketSendError {

}
