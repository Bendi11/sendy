use bytes::BufMut;

use crate::{net::msg::MessageKind, ser::{ToBytes, FromBytesError, FromBytes}, ctx::Context};

/// A variation of [ToBytes] that allows types to use the global [Context]'s state including crypto
/// keys
pub trait StatefulToBytes {
    fn write<W: bytes::BufMut>(&self, ctx: &Context, buf: W);
    fn size_hint(&self, ctx: &Context) -> Option<usize> { None }
}

/// A variation of [FromBytes] that allows types to use the global [Context]'s state including
/// crypto keys
pub trait StatefulFromBytes: Sized {
    fn parse(ctx: &Context, buf: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError>;
}


/// Trait satisfied by all types that can be serialized to bytes and sent to other nodes
pub trait Request: StatefulToBytes + StatefulFromBytes {
    /// The message identifier when the request is serialized
    const KIND: MessageKind;
}

pub trait Response: StatefulToBytes + StatefulFromBytes {}

/// Request sent to a remote peer requesting the node send certificates with public keys for
/// authentication and encryption
pub struct ConnectAuthenticateRequest {
    
}

impl<T: ToBytes> StatefulToBytes for T {
    fn write<B: BufMut>(&self, _: &Context, buf: B) { <Self as ToBytes>::write(self, buf) }
    fn size_hint(&self, _: &Context) -> Option<usize> { <Self as ToBytes>::size_hint(self) }
}

impl<T: FromBytes> StatefulFromBytes for T {
    fn parse(_: &Context, buf: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        <Self as FromBytes>::parse(buf) 
    }
}
