use std::ops::Deref;

use bytes::BufMut;
use rsa::{pkcs1v15::Signature, rand_core::OsRng, Pkcs1v15Encrypt};

use crate::{
    ctx::Context,
    model::channel::KeyedChannel,
    net::msg::MessageKind,
    ser::{FromBytes, FromBytesError, ToBytes},
    Peer,
};

pub mod connect;
pub mod invite;
pub mod post;

pub use connect::*;
pub use invite::*;

/// Trait satisfied by all types that can be serialized to bytes and sent to other nodes
pub trait Request: ToBytes + FromBytes {
    /// The message identifier when the request is serialized
    const KIND: MessageKind;
}

pub trait Response: ToBytes + FromBytes {}


/// Wrapper for a type that is signed with the private key before being sent to a remote, and
/// verified with a remote's public key when receieved
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed<T> {
    pub val: T,
    pub signature: Signature,
    pub valid: bool,
}
impl<T> Signed<T> {
    pub fn into_inner(self) -> T {
        self.val
    }
}
impl<T> Deref for Signed<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.val
    }
}
