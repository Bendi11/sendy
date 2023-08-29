//! Definitions for all messages that may be exchanged between peers

pub mod conn;

use crate::{sock::PacketKind, FromBytes, ToBytes};

pub use conn::Conn;

/// Trait to be implemented by all types that are meant to be transmitted between peers on the
/// network, containing the message kind tag to send alongside the encoded message body
pub trait Message: ToBytes + for<'a> FromBytes<'a> {
    const TAG: PacketKind;
}

/// A transaction is a request -> response procedure, defining the request type, and the two
/// possible response types for successful or erroneous results
pub trait Transaction {
    type Request: Message;
    type OkResponse: Message;
    type ErrResponse: Message;
}
