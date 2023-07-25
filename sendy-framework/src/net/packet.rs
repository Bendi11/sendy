use std::io::{Cursor, Read, Write};

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
pub struct PacketHeader {
    pub kind: PacketKind,
    /// ID of the message, rolls over to 1 after passing 255
    pub msgid: u8,
    /// Offset into message buffer (in blocks) to place the payload bytes
    pub msgoff: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Packet<P: PacketPayload> {
    pub header: PacketHeader,
    pub payload: P,
}

/// Trait to be implemented by all possible payloads for each type of packet available in the Sendy
/// protocol
pub trait PacketPayload: Sized {
    type Error;
    
    /// Consume bytes from the given buffer to parse an instance of `Self`, returning the remaining
    /// portion of the buffer and the instance or an error
    fn parse<R: Read>(buf: R) -> Result<Self, Self::Error>;
    
    /// Write the representation of this payload to a buffer of bytes
    fn write<W: Write>(&self, buf: W) -> Result<(), Self::Error>;
}


impl PacketPayload for () {
    type Error = std::convert::Infallible;

    fn parse<R: Read>(_: R) -> Result<Self, Self::Error> { Ok(()) }
    fn write<W: Write>(&self, _: W) -> Result<(), Self::Error> { Ok(()) }
}

impl PacketPayload for Vec<u8> {
    type Error = std::io::Error;

    fn parse<R: Read>(mut read: R) -> Result<Self, Self::Error> {
        let mut this = Vec::new();
        read.read_to_end(&mut this)?;
        Ok(this)
    }
    
    fn write<W: Write>(&self, mut buf: W) -> Result<(), Self::Error> {
        buf.write_all(&self)
    }
}

impl PacketPayload for PacketHeader {
    type Error = PacketHeaderParseError;

    fn parse<R: Read>(mut buf: R) -> Result<Self, Self::Error> {
        let kind = buf.read_u8()?;
        let kind = PacketKind::try_from(kind)?;
        let msgid = buf.read_u8()?;
        let msgoff = buf.read_u32::<LE>()?;

        Ok(Self {
            kind,
            msgid,
            msgoff,
        })
    }

    fn write<W: Write>(&self, mut buf: W) -> Result<(), Self::Error> {
        buf.write_u8(self.kind as u8)?;
        buf.write_u8(self.msgid)?;
        buf.write_u32::<LE>(self.msgoff)?;

        Ok(())
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
