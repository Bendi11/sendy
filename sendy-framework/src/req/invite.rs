use bytes::BufMut;

use crate::{
    model::channel::UnkeyedChannel, net::msg::MessageKind, FromBytes, FromBytesError, ToBytes,
};

use super::{Request, Response};

/// Request sent to invite a remote peer to a channel
#[derive(Debug)]
pub struct ChannelInviteRequest {
    /// The channel that we are inviting a peer to, contains all **SECRET** information needed to
    /// derive the channel public key
    pub channel: UnkeyedChannel,
}

/// Response sent to a peer that has invited us to a channel
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelInviteResponse {
    ChannelJoined = 1,
    ChannelNotJoined = 2,
}

impl ChannelInviteRequest {

}

impl Request for ChannelInviteRequest {
    const KIND: MessageKind = MessageKind::InviteToChannel;
}
impl Response for ChannelInviteResponse {}
impl ToBytes for ChannelInviteRequest {
    fn write<W: bytes::BufMut>(&self, buf: W) {
        self.channel.write(buf)
    }
}
impl FromBytes for ChannelInviteRequest {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let channel = UnkeyedChannel::parse(reader)?;
        Ok(Self {
            channel,
        })
    }
}

impl ToBytes for ChannelInviteResponse {
    fn write<W: BufMut>(&self, buf: W) {
        (*self as u8).write(buf)
    }

    fn size_hint(&self) -> Option<usize> {
        (*self as u8).size_hint()
    }
}
impl FromBytes for ChannelInviteResponse {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let tag = reader.read_byte()?;
        match tag {
            1 => Ok(Self::ChannelJoined),
            2 => Ok(Self::ChannelNotJoined),
            other => Err(FromBytesError::Parsing(format!("Unknown channel invite response tag {:X}", other))),
        }
    }
}
