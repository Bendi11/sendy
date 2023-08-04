use bytes::BufMut;

use crate::{net::msg::MessageKind, ctx::Context, Peer, model::channel::UnkeyedChannel, ToBytes, FromBytes, FromBytesError};

use super::{Request, StatefulToBytes, Encrypted, Signed, StatefulFromBytes, Response, SerializationState};


/// Request sent to invite a remote peer to a channel
#[derive(Debug)]
pub struct ChannelInviteRequest {
    /// The channel that we are inviting a peer to, contains all **SECRET** information needed to
    /// derive the channel public key
    pub channel: Signed<Encrypted<UnkeyedChannel>>,
}

/// Response sent to a peer that has invited us to a channel
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelInviteResponse {
    ChannelJoined = 1,
    ChannelNotJoined = 2,
}


impl Request for ChannelInviteRequest {
    const KIND: MessageKind = MessageKind::InviteToChannel;
}
impl StatefulToBytes for ChannelInviteRequest {
    fn stateful_write<W: bytes::BufMut>(&self, state: SerializationState<'_>, buf: W) {
        self.channel.stateful_write(state, buf)
    }
}

impl StatefulFromBytes for ChannelInviteRequest {
    fn stateful_parse(state: SerializationState<'_>, buf: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        Signed::<Encrypted::<UnkeyedChannel>>::stateful_parse(state, buf).map(|channel| Self { channel })
    }
}

impl Response for ChannelInviteResponse {}
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
        Ok(match tag {
            1 => Self::ChannelJoined,
            2 => Self::ChannelNotJoined,
            other => return Err(FromBytesError::Parsing(format!("Unknown channel invite response tag: {}", other)))
        })
    }
}
