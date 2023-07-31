use std::num::NonZeroU8;

use bytes::Bytes;
use rsa::RsaPublicKey;

use super::sock::PacketKind;
use crate::{ser::{FromBytes, FromBytesError, ToBytes}, req::{Request, Response}};

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

impl TryFrom<u8> for MessageKind {
    type Error = FromBytesError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value.checked_sub(PacketKind::MSG_TAG_OFFSET) {
            Some(0) => Self::Test,
            Some(1) => Self::Respond,
            Some(2) => Self::AuthConnect,
            _ => {
                return Err(FromBytesError::Parsing(format!(
                    "Invalid message kind {:X}",
                    value
                )))
            }
        })
    }
}

#[derive(Clone, Debug)]
pub struct TestMessage(pub RsaPublicKey);

impl Response for TestMessage {}
impl Request for TestMessage {
    const KIND: MessageKind = MessageKind::Test;
}

impl FromBytes for TestMessage {
    fn parse(buf: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        Ok(Self(RsaPublicKey::parse(buf)?)) 
    }
}

impl ToBytes for TestMessage {
    fn write<W: bytes::BufMut>(&self, buf: W) {
        self.0.write(buf)
    }
}
