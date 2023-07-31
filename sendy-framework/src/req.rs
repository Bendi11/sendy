use bytes::BufMut;

use crate::{net::msg::MessageKind, ser::{ToBytes, FromBytesError, FromBytes}, ctx::Context, model::crypto::SignedCertificate};

/// A variation of [ToBytes] that allows types to use the global [Context]'s state including crypto
/// keys
pub trait StatefulToBytes {
    fn stateful_write<W: bytes::BufMut>(&self, ctx: &Context, buf: W);
    fn stateful_size_hint(&self, ctx: &Context) -> Option<usize> { None }
}

/// A variation of [FromBytes] that allows types to use the global [Context]'s state including
/// crypto keys
pub trait StatefulFromBytes: Sized {
    fn stateful_parse(ctx: &Context, buf: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError>;
}


/// Trait satisfied by all types that can be serialized to bytes and sent to other nodes
pub trait Request: StatefulToBytes + StatefulFromBytes {
    /// The message identifier when the request is serialized
    const KIND: MessageKind;
}

pub trait Response: StatefulToBytes + StatefulFromBytes {}

/// Request sent to a remote peer requesting the node send certificates with public keys for
/// authentication and encryption
pub struct ConnectAuthenticateRequest;

/// Response sent to a [ConnectAuthenticateRequest] with signed certificate
pub struct ConnectAuthenticateResponse {
    pub cert: SignedCertificate,
}

impl Response for ConnectAuthenticateResponse {}

impl ToBytes for ConnectAuthenticateResponse {
    fn write<W: BufMut>(&self, buf: W) {
        self.cert.write(buf)
    }

    fn size_hint(&self) -> Option<usize> {
        self.cert.size_hint()
    }
}

impl FromBytes for ConnectAuthenticateResponse {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        Ok(Self {
            cert: SignedCertificate::parse(reader)?,
        })
    }
}

impl ToBytes for ConnectAuthenticateRequest {
    fn write<W: BufMut>(&self, buf: W) {}
    fn size_hint(&self) -> Option<usize> { Some(0) }
}

impl FromBytes for ConnectAuthenticateRequest {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        Ok(Self)
    }
}

impl Request for ConnectAuthenticateRequest {
    const KIND: MessageKind = MessageKind::AuthConnect;
}

impl<T: ToBytes> StatefulToBytes for T {
    fn stateful_write<B: BufMut>(&self, _: &Context, buf: B) { <Self as ToBytes>::write(self, buf) }
    fn stateful_size_hint(&self, _: &Context) -> Option<usize> { <Self as ToBytes>::size_hint(self) }
}

impl<T: FromBytes> StatefulFromBytes for T {
    fn stateful_parse(_: &Context, buf: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        <Self as FromBytes>::parse(buf) 
    }
}
