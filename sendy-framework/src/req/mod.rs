use std::ops::Deref;

use bytes::BufMut;
use rsa::{pkcs1v15::Signature, rand_core::OsRng, Pkcs1v15Encrypt};

use crate::{
    ctx::ContextInternal,
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
