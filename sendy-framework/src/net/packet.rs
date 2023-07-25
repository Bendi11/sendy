
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketKind {
    Conn = 0,
    Ack = 1,
}

#[derive(Clone, Copy, Debug)]
pub struct PacketHeader {
    pub kind: PacketKind,
    pub msgid: u16,
    pub seqno: u32,
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
    fn parse(buf: &[u8]) -> Result<(&[u8], Self), Self::Error> where
        PacketParseError: From<Self::Error>;
    
    /// Write the representation of this payload to a buffer of bytes
    fn write(&self, buf: &mut Vec<u8>);
}


impl PacketPayload for () {
    type Error = std::convert::Infallible;

    fn parse(buf: &[u8]) -> Result<(&[u8], Self), Self::Error> {
        Ok((buf, ()))
    }

    fn write(&self, buf: &mut Vec<u8>) {

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
    #[error("Failed to parse kind: {0}")]
    Kind(#[from] PacketKindParseErr),
}
