use std::{fmt, num::NonZeroU8};

use bytes::BufMut;

use crate::{
    ser::{FromBytes, FromBytesError, ToBytes, ByteWriter, ToBytesError},
};

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
    /// Signals that the following payload bytes are the response to a request made by the message
    /// ID of the respond packet's header
    Respond = 3,
}

impl ToBytes for PacketId {
    fn encode<W: BufMut>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        buf.put_u8(self.msgid.get());
        buf.put_u16_le(self.blockid);
        Ok(())
    }

    fn size_hint(&self) -> usize {
        self.msgid.get().size_hint() +
        self.blockid.size_hint()
    }
}

impl FromBytes for PacketId {
    fn decode(buf: &mut untrusted::Reader) -> Result<Self, FromBytesError> {
        let msgid = u8::decode(buf)?;
        let msgid = NonZeroU8::new(msgid).ok_or_else(|| {
            FromBytesError::Parsing("Packet ID with invalid message ID 0".to_owned())
        })?;

        let blockid = u16::decode(buf)?;
        Ok(Self { msgid, blockid })
    }
}

impl ToBytes for PacketHeader {
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        self.kind.encode(buf)?;
        self.id.encode(buf)?;
        self.checksum.encode(buf)?;
        Ok(())
    }
}

impl FromBytes for PacketHeader {
    fn decode(buf: &mut untrusted::Reader) -> Result<Self, FromBytesError> {
        let kind = PacketKind::decode(buf)?;
        let id = PacketId::decode(buf)?;
        let checksum = u32::decode(buf)?;

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
    fn decode(buf: &mut untrusted::Reader) -> Result<Self, FromBytesError> {
        let value = u8::decode(buf)?;
        Ok(match value {
            0 => Self::Conn,
            1 => Self::Ack,
            2 => Self::Transfer,
            3 => Self::Respond,
            _ => return Err(FromBytesError::Parsing(format!("Invalid packet kind tag {:X}", value))),
        })
    }
}

impl ToBytes for PacketKind {
    fn encode<W: BufMut>(&self, buf: &mut W) -> Result<(), ToBytesError>  {
        let v = match self {
            Self::Conn => 0,
            Self::Ack => 1,
            Self::Transfer => 2,
            Self::Respond => 3,
        };
        buf.put_u8(v);
        Ok(())
    }
}

impl fmt::Display for PacketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.msgid, self.blockid)
    }
}
