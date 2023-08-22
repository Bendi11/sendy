mod net;
mod ser;
mod crypto;


use crypto::PrivateKeychain;
use net::sock::ReliableSocket;
pub use ser::{FromBytes, FromBytesError, ToBytes};


/// The main interface for interacting with the Sendy network - contains state for all peer
/// connections and resource persistence
#[derive(Debug,)]
pub struct Context {
    /// Manager for all lower-level UDP operations
    socks: ReliableSocket,
    /// Keychain used to sign and encrypt messages
    keychain: PrivateKeychain,
}
