use std::{fmt, num::NonZeroU8};

use bytes::BufMut;

use crate::{net::msg::{MessageKind}, ser::{FromBytes, ToBytes, FromBytesError}};

/// 'minimum maximum reassembly buffer size' guaranteed to be deliverable, minus IP and UDP headers
pub(crate) const MAX_SAFE_UDP_PAYLOAD: usize = 500;

/// The encoded size of a [PacketHeader] in bytes
pub(crate) const HEADER_SZ: usize = 8;

pub(in crate::net::sock) const CHECKSUM_OFFSET: usize = 4;
pub(in crate::net::sock) const BLOCKID_OFFSET: usize = 2;
#[allow(dead_code)]
pub(in crate::net::sock) const MSGID_OFFSET: usize = 1;

/// The space available to a single packet for payload, after IP, UDP, and Sendy headers
pub(crate) const BLOCK_SIZE: usize = MAX_SAFE_UDP_PAYLOAD - HEADER_SZ;

/// An 8 byte packet header with packet identifiers, checksum, and packet kind markers
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PacketHeader {
    /// 1 byte representing the kind of packet this is, see [PacketKind] for usage
    pub kind: PacketKind,
    /// The message and block id of this packet, see [PacketId] for usage
    pub id: PacketId,
    /// CRC32 checksum of the following payload bytes
    pub checksum: u32,
}

/// A 3 byte unique identifier placed at the top of each UDP packet
///
/// Contains a message ID, identifying the message that this packet's payload is a part of,
/// and a block id, identifying where in the receiver's message buffer the payload bytes should be
/// placed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PacketId {
    /// ID of the message, rolls over to 1 after passing 255 because
    /// 0 is reserved to mark invalid / not received packets
    pub msgid: NonZeroU8,
    /// Offset into receiver's message buffer (in MAX_BLOCK_SIZE blocks, NOT bytes) to place the packet's payload bytes
    pub blockid: u16,
}

/// Unique identifier assigned to each packet, identifies the purpose of the packet
///
/// There are two primary kinds of packets sent:
/// ## Control:
///  - Control packets are single packets with payload sizes under the MAX_SAFE_UDP_PAYLOAD
///  - Used to transfer messages between nodes for metadata like window sizes
/// ## Message:
///  - Message packets signal the beginning of a TRANSFER packet stream
///  - Message packets are used for application-level messaging between nodes
///  - The `blockid` field of a message packet should signal the total size of the incoming
///  message in MAX_BLOCK_SIZE blocks, and the payload is always copied to the message buffer at
///  offset 0
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketKind {
    /// Used to connect to other nodes with hole punching
    Conn = 0,
    /// Used to signal that a packet identified by the [PacketId] of the header has been received
    Ack = 1,
    /// Signals that the following payload bytes are to be placed at the offset into the message
    /// given by the [PacketId] of the header
    Transfer = 2,

    /// An application-level message packet
    Message(MessageKind),
}

/// Unit struct that implements the [Message] trait with no payload, allowing the lower-level
/// functions to send ACK packets with the same interface as other messages
#[derive(Clone, Copy, Debug)]
pub(crate) struct AckMessage;

impl FromBytes for AckMessage {
    fn parse(_: &mut untrusted::Reader) -> Result<Self, FromBytesError> {
        Ok(Self)
    }
}
impl ToBytes for AckMessage {
    fn write<W: BufMut>(&self, _: W) {}
}

impl PacketKind {
    /// The tag to be used for the message tag with the lowest ID in the
    /// [MessageKind] enum
    pub const MSG_TAG_OFFSET: u8 = 3;
}

impl ToBytes for PacketId {
    fn write<W: BufMut>(&self, mut buf: W) {
        buf.put_u8(self.msgid.get());
        buf.put_u16_le(self.blockid);
    }
}

impl FromBytes for PacketId {
    fn parse(buf: &mut untrusted::Reader) -> Result<Self, FromBytesError> {
        let msgid = u8::parse(buf)?;
        let msgid = NonZeroU8::new(msgid).ok_or_else(||
                FromBytesError::Parsing("Packet ID with invalid message ID 0".to_owned()),
        )?;

        let blockid = u16::parse(buf)?;
        Ok(Self { msgid, blockid })
    }
}

impl ToBytes for PacketHeader {
    fn write<W: BufMut>(&self, mut buf: W) {
        self.kind.write(&mut buf);
        self.id.write(&mut buf);
        buf.put_u32_le(self.checksum);
    }
}

impl FromBytes for PacketHeader {
    fn parse(buf: &mut untrusted::Reader) -> Result<Self, FromBytesError> {
        let kind = PacketKind::parse(buf)?;
        let id = PacketId::parse(buf)?;
        let checksum = u32::parse(buf)?;

        Ok(Self { kind, id, checksum })
    }
}

impl PacketKind {
    /// If the packet is a control packet that will not be followed by more [PacketKind::Transfer]
    /// packets, see [PacketKind] for more
    pub const fn is_control(&self) -> bool {
        match self {
            Self::Conn | Self::Ack => true,
            _ => false,
        }
    }
}

impl FromBytes for PacketKind {
    fn parse(buf: &mut untrusted::Reader) -> Result<Self, FromBytesError> {
        let value = u8::parse(buf)?;
        Ok(match value {
            0 => Self::Conn,
            1 => Self::Ack,
            2 => Self::Transfer,
            other => Self::Message(MessageKind::try_from(other)?),
        })
    }
}

impl ToBytes for PacketKind {
    fn write<W: BufMut>(&self, mut buf: W) {
        let v = match self {
            Self::Conn => 0,
            Self::Ack => 1,
            Self::Transfer => 2,
            Self::Message(msg) => *msg as u8,
        };
        buf.put_u8(v);
    }
}

impl fmt::Display for PacketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.msgid, self.blockid)
    }
}
