use std::{io::{Cursor, Read}, num::NonZeroU8};

use tokio::{net::UdpSocket, sync::Mutex};

use super::packet::{PacketHeader, PacketPayload, PacketKind, PacketHeaderParseError, Packet};


const MAX_IN_TRANSIT_MSG: usize = 5;
const MAX_PACKET_SZ: usize = 500;
const HEADER_SZ: usize = 6;
const BLOCK_SIZE: usize = MAX_PACKET_SZ - HEADER_SZ;
const INVALID_MSG_ID: u8 = 0;

/// Minimal reliability layer over a UDP connection
#[derive(Debug)]
struct ReliableSocket {
    sock: UdpSocket,
    recv: Mutex<[RecvMessage ; MAX_IN_TRANSIT_MSG]>,
}

#[derive(Debug)]
struct RecvMessage {
    pub id: Option<NonZeroU8>,
    pub data: Vec<u8>,
    pub last_block: u32,
    pub kind: PacketKind,
}

impl ReliableSocket {
    pub async fn recv(&self) -> Result<(PacketKind, Vec<u8>), ReliableSocketRecvError> {
        let mut buf = [0u8 ; MAX_PACKET_SZ];
        loop {
            self.sock.recv(&mut buf).await.unwrap();
            let mut buf = Cursor::new(&buf);
            let header = PacketHeader::parse(&mut buf).unwrap();

            if header.kind.is_control() {
                self.send(Packet::new(PacketHeader {
                    kind: PacketKind::Conn,
                    msgid: header.msgid,
                    msgoff: 0,
                })).await;
                return Ok((header.kind, vec![]))
            }

            let mut recv = self.recv.lock().await;
            let msg_slot = if header.kind == PacketKind::Transfer {
                recv
                    .iter()
                    .filter_map(|(idx, id)| id.map(|id| (idx, id)))
                    .find_map(|(idx, id)| (id.get() == header.msgid).then_some(idx))
                    .ok_or_else(|| ReliableSocketRecvError::TransferMessageId(header.msgid))?
            } else {
                let open_slot = recv.msg_ids
                    .iter()
                    .enumerate()
                    .find_map(|(idx, id)| id.is_some().then_some(idx));

                match open_slot {
                    Some(slot) => {
                        let new_id = NonZeroU8::new(header.msgid)
                            .ok_or_else(|| ReliableSocketRecvError::InvalidMsgId)?;

                        recv.msg_ids[slot] = Some(new_id);
                        recv.msg_data[slot].reserve(BLOCK_SIZE * header.msgoff as usize);
                        recv.msg_block_counts[slot] = header.msgoff;
                        recv.msg_kinds[slot] = header.kind;

                        slot
                    },
                    None => return Err(ReliableSocketRecvError::NoOpenSlot),
                }
            };

            buf.read_to_end(&mut recv.msg_data[msg_slot])?;
            recv.msg_block_counts[msg_slot] -= 1;
            if recv.msg_block_counts[msg_slot] == 0 {
                recv.msg_ids[msg_slot] = None;
                let data = std::mem::take(&mut recv.msg_data[msg_slot]);
                return Ok((recv.msg_kinds[msg_slot], data))
            }
        }
    }

    pub async fn send<P: PacketPayload>(&self, packet: Packet<P>) -> Result<(), ReliableSocketSendError> {
        
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
