use std::ops::Deref;

use bytes::BufMut;
use rsa::{Pkcs1v15Encrypt, rand_core::OsRng};

use crate::{net::msg::MessageKind, ser::{ToBytes, FromBytesError, FromBytes}, ctx::Context, model::{crypto::SignedCertificate, channel::UnkeyedChannel}, Peer};

/// A variation of [ToBytes] that allows types to use the global [Context]'s state including crypto
/// keys
pub trait StatefulToBytes {
    fn stateful_write<W: bytes::BufMut>(&self, ctx: &Context, peer: &Peer, buf: W);
    fn stateful_size_hint(&self, _: &Context, _: &Peer) -> Option<usize> { None }
    
    /// Shortcut to write the given type to a buffer of bytes
    fn stateful_write_to_vec(&self, ctx: &Context, peer: &Peer) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.stateful_size_hint(ctx, peer).unwrap_or(0));
        self.stateful_write(ctx, peer, &mut buf);
        buf
    }
}

/// A variation of [FromBytes] that allows types to use the global [Context]'s state including
/// crypto keys
pub trait StatefulFromBytes: Sized {
    fn stateful_parse(ctx: &Context, peer: &Peer, buf: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError>;

    /// Helper function to read an instance of [self] without needing to create [untrusted] types
    fn stateful_read_from_slice(ctx: &Context, peer: &Peer, slice: &[u8]) -> Result<Self, FromBytesError> {
        let mut reader = untrusted::Reader::new(untrusted::Input::from(slice));
        Self::stateful_parse(ctx, peer, &mut reader)
    }

}


/// Trait satisfied by all types that can be serialized to bytes and sent to other nodes
pub trait Request: StatefulToBytes + StatefulFromBytes {
    /// The message identifier when the request is serialized
    const KIND: MessageKind;
}

pub trait Response: StatefulToBytes + StatefulFromBytes {}

/// Wrapper for a type that is encrypted before being sent to a remote, or decrypted before being
/// read from a remote peer
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Encrypted<T>(T);

impl<T> Deref for Encrypted<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Request sent to a remote peer requesting the node send certificates with public keys for
/// authentication and encryption
pub struct ConnectAuthenticateRequest;
impl Request for ConnectAuthenticateRequest {
    const KIND: MessageKind = MessageKind::AuthConnect;
}

/// Response sent to a [ConnectAuthenticateRequest] with signed certificate
pub struct ConnectAuthenticateResponse {
    pub cert: SignedCertificate,
}
impl Response for ConnectAuthenticateResponse {}

/// Request sent to invite a remote peer to a channel
#[derive(Debug)]
pub struct ChannelInviteRequest {
    /// The channel that we are inviting a peer to, contains all **SECRET** information needed to
    /// derive the channel public key
    pub channel: UnkeyedChannel,
}

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
    fn write<W: BufMut>(&self, _: W) {}
    fn size_hint(&self) -> Option<usize> { Some(0) }
}
impl FromBytes for ConnectAuthenticateRequest {
    fn parse(_: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        Ok(Self)
    }
}


impl<T: ToBytes> StatefulToBytes for T {
    fn stateful_write<B: BufMut>(&self, _: &Context, _: &Peer, buf: B) { <Self as ToBytes>::write(self, buf) }
    fn stateful_size_hint(&self, _: &Context, _: &Peer) -> Option<usize> { <Self as ToBytes>::size_hint(self) }
}
impl<T: FromBytes> StatefulFromBytes for T {
    fn stateful_parse(_: &Context, _: &Peer, buf: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        <Self as FromBytes>::parse(buf) 
    }
}

impl<T: StatefulToBytes> StatefulToBytes for Encrypted<T> {
    fn stateful_write<W: BufMut>(&self, ctx: &Context, peer: &Peer, mut buf: W) {
        let bytes = self.0.stateful_write_to_vec(ctx, peer);
        let encrypted = match peer
            .remote_keys()
            .enc
            .encrypt(
                &mut OsRng,
                Pkcs1v15Encrypt,
                &bytes
            ) {
                Ok(b) => b,
                Err(e) => {
                    log::error!("Failed to encrypt bytes: {}", e);
                    return
                }
            };

        (encrypted.len() as u32).write(&mut buf);
        buf.put_slice(&encrypted);
    }
}

impl<T: StatefulFromBytes> StatefulFromBytes for Encrypted<T> {
    fn stateful_parse(ctx: &Context, peer: &Peer, buf: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let len = u32::parse(buf)?;
        let encrypted = buf.read_bytes(len as usize)?.as_slice_less_safe();
        let decrypted = ctx.keychain.enc.decrypt(Pkcs1v15Encrypt, encrypted)
            .map_err(|e| FromBytesError::Parsing(format!("Failed to decrypt a message: {}", e)))?;

        T::stateful_read_from_slice(ctx, peer, &decrypted).map(Self)
    }
}
