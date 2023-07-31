use std::num::NonZeroU8;

use bytes::Bytes;

use super::sock::PacketKind;
use crate::ser::{ToBytes, FromBytes, FromBytesError};

/// An enumeration over all application layer messages that may be passed between nodes
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    Test = PacketKind::MSG_TAG_OFFSET,
    /// Signals that the following message introduction is in response to an already-sent message - 
    /// the message ID of the packet is the message that this is reponding to
    Respond = PacketKind::MSG_TAG_OFFSET + 1,
    /// Transfer authentication public key + certificate and encryption public key
    AuthConnect = PacketKind::MSG_TAG_OFFSET + 2,
}

/// A message that has been received from a remote peer, but has not yet been parsed to a message
/// type
#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    /// Received message kind, used to instruct parsing
    pub kind: MessageKind,
    /// ID of the message as it was transmitted by the peer
    pub(crate) id: NonZeroU8,
    /// The payload of the message
    pub bytes: Bytes,
}

/// Trait satisfied by all types that can be serialized to bytes and sent to other nodes
pub trait Request: ToBytes + FromBytes {
    const KIND: MessageKind;
}

pub trait Response: ToBytes + FromBytes {}

impl TryFrom<u8> for MessageKind {
    type Error = FromBytesError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value.checked_sub(PacketKind::MSG_TAG_OFFSET) {
            Some(0) => Self::Test,
            Some(1) => Self::Respond,
            Some(2) => Self::AuthConnect,
            _ => {
                return Err(FromBytesError::Parsing(format!("Invalid message kind {:X}", value)))
            }
        })
    }
}

#[derive(Clone, Debug)]
pub struct TestMessage(pub Vec<u8>);

impl Request for TestMessage {
    const KIND: MessageKind = MessageKind::Test;
}

impl Response for TestMessage {}

impl FromBytes for TestMessage {
    fn parse(buf: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        Ok(Self(
            buf.read_bytes_to_end().as_slice_less_safe().to_owned()
        ))
    }
}

impl ToBytes for TestMessage {
    fn write<W: bytes::BufMut>(&self, mut buf: W) {
        buf.put_slice(&self.0[..]);
    }
}
