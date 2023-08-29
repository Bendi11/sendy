//! # Sendy Network Protocol
//!
//! A crate for interacting with the sendy p2p messaging protocol designed to allow small networks
//! of friends to communicate via text without the need for a central server.
//!
//! All operations can be accessed by the [Context] struct, which should be wrapped in an `Arc`

pub(crate) mod sock;
pub(crate) mod ser;
pub(crate) mod msg;
pub(crate) mod ctx;

pub mod model;
pub use sock::SocketConfig;
pub use rsa;
pub use ser::{FromBytes, FromBytesError, ToBytes};
pub use ctx::Context;
