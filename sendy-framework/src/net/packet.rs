use std::io::{Cursor, Read, Write, ErrorKind};

use byteorder::{LittleEndian, ReadBytesExt, LE, WriteBytesExt};


#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketKind {
    Conn = 0,
    Ack = 1,

    Test = 2,
    /// Transfer bytes to a queued buffer
    Transfer = 3,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PacketHeader {
    pub kind: PacketKind,
    /// ID of the message, rolls over to 1 after passing 255
    pub msgid: u8,
    /// Offset into message buffer (in blocks) to place the payload bytes
    pub blockid: u32,
}

macro_rules! message {
    ($name:ident $tag:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub(crate) struct $name;
        impl Message for $name { const TAG: PacketKind = PacketKind::$tag; }
        impl ToBytes for $name { fn write<W: Write>(&self, buf: W) -> Result<(), std::io::Error> { Ok(()) } }
        impl FromBytes for $name { fn parse<R: Read>(buf: R) -> Result<Self, std::io::Error> { Ok(Self) } }
    };
}

message!{AckMessage Ack}
message!{TestMessage Test}
message!{ConnMessage Conn}

pub trait Message: Sized + ToBytes + FromBytes {
    const TAG: PacketKind;
}

/// Trait to be implemented by all possible payloads for each type of packet available in the Sendy
/// protocol
pub trait ToBytes: Sized {
    /// Write the representation of this payload to a buffer of bytes
    fn write<W: Write>(&self, buf: W) -> Result<(), std::io::Error>;
}

pub trait FromBytes: Sized {
    fn parse<R: Read>(buf: R) -> Result<Self, std::io::Error>;
}


impl ToBytes for () {
    fn write<W: Write>(&self, _: W) -> Result<(), std::io::Error> { Ok(()) }
}

impl FromBytes for () {
    fn parse<R: Read>(buf: R) -> Result<Self, std::io::Error> {
        Ok(())
    }
}

impl ToBytes for &[u8] {
    fn write<W: Write>(&self, mut buf: W) -> Result<(), std::io::Error> {
        buf.write_all(&self)
    }
}

impl ToBytes for PacketHeader {
    fn write<W: Write>(&self, mut buf: W) -> Result<(), std::io::Error> {
        buf.write_u8(self.kind as u8)?;
        buf.write_u8(self.msgid)?;
        buf.write_u32::<LE>(self.blockid)?;

        Ok(())
    }
}

impl FromBytes for PacketHeader {
    fn parse<R: Read>(mut buf: R) -> Result<Self, std::io::Error> {
        let kind = buf.read_u8()?;
        
        let kind = PacketKind::try_from(kind)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?;

        let msgid = buf.read_u8()?;
        let blockid = buf.read_u32::<LE>()?;

        Ok(Self {
            kind,
            msgid,
            blockid,
        })
    }
}

impl PacketKind {
    /// If the packet is a control packet that will not send more bytes
    pub const fn is_control(&self) -> bool {
        match self {
            Self::Conn 
            | Self::Ack => true,
            _ => false,
        }
    }
}

impl TryFrom<u8> for PacketKind {
    type Error = PacketKindParseErr;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::Conn,
            1 => Self::Ack,
            2 => Self::Test,
            3 => Self::Transfer,
            other => return Err(PacketKindParseErr(other))
        })
    } 
}

#[derive(Debug, thiserror::Error)]
#[error("Invalid packet type identifier: {0}")]
pub struct PacketKindParseErr(pub u8);

#[derive(Debug, thiserror::Error)]
pub enum PacketParseError {
    #[error("Failed to parse packet header: {0}")]
    Header(#[from] PacketHeaderParseError),
}

#[derive(Debug, thiserror::Error)]
pub enum PacketHeaderParseError {
    #[error("Failed to parse packet kind: {0}")]
    Kind(#[from] PacketKindParseErr),

    #[error("I/O Error: {0}")]
    IO(#[from] std::io::Error),
}
