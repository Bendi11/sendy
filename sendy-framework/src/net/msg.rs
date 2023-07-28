use bytes::{BufMut, Bytes};

use super::sock::{PacketKind, ToBytes, FromBytes};


/// An enumeration over all application layer messages that may be passed between nodes
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    Test = PacketKind::MSG_TAG_OFFSET,
}

/// A message that has been received from a remote peer, but has not yet been parsed to a message
/// type
#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    /// Received message kind, used to instruct parsing
    pub kind: MessageKind,
    /// The payload of the message
    pub bytes: Bytes,
}

/// Trait satisfied by all types that can be serialized to bytes and sent to other nodes
pub trait Message: ToBytes + FromBytes {
    const KIND: PacketKind;
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

#[derive(Clone, Debug)]
pub struct TestMessage(pub Vec<u8>);

impl Message for TestMessage {
    const KIND: PacketKind = PacketKind::Message(MessageKind::Test);
}

impl FromBytes for TestMessage {
    fn parse<R: bytes::Buf>(rbuf: R) -> Result<Self, std::io::Error> {
        let mut buf = vec![];
        buf.put(rbuf);
        Ok(Self(buf))
    }
}

impl ToBytes for TestMessage {
    fn write<W: bytes::BufMut>(&self, mut buf: W) {
        buf.put_slice(&self.0[..]);
    }
}
