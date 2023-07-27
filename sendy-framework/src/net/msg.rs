use super::sock::{PacketKind, ToBytes, FromBytes};


/// An enumeration over all application layer messages that may be passed between nodes
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    Test = PacketKind::MSG_TAG_OFFSET,
}

/// Trait satisfied by all types that can be serialized to bytes and sent to other nodes
pub trait Message: ToBytes + FromBytes {
    const KIND: MessageKind;
}

impl TryFrom<u8> for MessageKind {
    type Error = std::io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            PacketKind::MSG_TAG_OFFSET => Self::Test,
            _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid message kind"))
        })
    }
}
