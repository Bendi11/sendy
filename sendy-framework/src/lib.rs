//! # Sendy Network Protocol
//!
//! A crate for interacting with the sendy p2p messaging protocol designed to allow small networks
//! of friends to communicate via text without the need for a central server.
//!
//! All operations can be accessed by the [Context] struct, which should be wrapped in an `Arc`

pub(crate) mod ctx;
pub(crate) mod msg;
pub(crate) mod sock;

pub mod model;
pub use ctx::Context;
pub use rsa;
pub use sock::SocketConfig;

pub use sendy_wireformat::{ByteWriter, FromBytes, FromBytesError, ToBytes, ToBytesError};
