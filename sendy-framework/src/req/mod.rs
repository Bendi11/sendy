use std::ops::Deref;

use bytes::BufMut;
use rsa::{Pkcs1v15Encrypt, rand_core::OsRng, pkcs1v15::Signature};

use crate::{net::msg::MessageKind, ser::{ToBytes, FromBytesError, FromBytes}, ctx::Context, Peer};

pub mod invite;
pub mod connect;

pub use invite::*;
pub use connect::*;

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

impl<T> Encrypted<T> {
    pub fn into_inner(self) -> T { self.0 }
}
impl<T> Deref for Encrypted<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Wrapper for a type that is signed with the private key before being sent to a remote, and
/// verified with a remote's public key when receieved
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Signed<T>(T);
impl<T> Signed<T> {
    pub fn into_inner(self) -> T { self.0 }
}
impl<T> Deref for Signed<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
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

impl<T: StatefulToBytes> StatefulToBytes for Signed<T> {
    fn stateful_write<W: bytes::BufMut>(&self, ctx: &Context, peer: &Peer, mut buf: W) {
        use rsa::signature::Signer;
        let encoded = self.0.stateful_write_to_vec(ctx, peer);
        let signature = ctx.keychain.auth.sign(&encoded);
        buf.put_slice(&encoded);
        signature.write(&mut buf);
    }
}
impl<T: StatefulFromBytes> StatefulFromBytes for Signed<T> {
    fn stateful_parse(ctx: &Context, peer: &Peer, buf: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        use rsa::signature::Verifier;
        let (read, val) = buf.read_partial(|rdr| T::stateful_parse(ctx, peer, rdr))?;
        let sig = Signature::parse(buf)?;
        
        if let Err(e) = peer.remote_keys().auth.verify(read.as_slice_less_safe(), &sig) {
            return Err(FromBytesError::Parsing(format!("Failed to verify signature from {}: {}", peer.remote().ip(), e)))
        }

        Ok(Self(val))
    }
}
