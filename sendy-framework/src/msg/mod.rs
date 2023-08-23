//! Definitions for all messages that may be exchanged between peers

mod conn;

use crate::{sock::PacketKind, ToBytes, FromBytes};

pub use conn::Conn;

/// Trait to be implemented by all types that are meant to be transmitted between peers on the
/// network, containing the message kind tag to send alongside the encoded message body
pub trait Message<'a>: ToBytes + FromBytes<'a> {
    const TAG: PacketKind;
}