//! Model for peer certificates containing identification, authentication, and capabilities

use std::net::IpAddr;

use bitflags::bitflags;
use chrono::{DateTime, Duration, Utc};
use rsa::pkcs1v15::Signature;

use crate::{ByteWriter, FromBytes, FromBytesError, ToBytes, ToBytesError};

use super::crypto::PublicKeychain;

/// A peer's certificate that is meant to fully introduce one peer to another, without the
/// accompanying signature
#[derive(Clone, Debug, ToBytes, FromBytes)]
pub struct UnsignedPeerCertificate {
    /// The public keys used to verify the authenticity of messages sent by this peer and encrypt
    /// messages meant for this peer
    pub keychain: PublicKeychain,
    /// Supported extensions to the protocol
    pub capabilities: PeerCapabilities,
    /// Self-assigned username of this peer
    pub username: String,
    /// IP address of this peer
    pub sockaddr: IpAddr,
    /// Time that this certificate will be valid from
    pub timestamp: DateTime<Utc>,
    /// How long past `timestamp` this certificate will still be valid
    pub ttl: Duration,
}

#[derive(Clone, Debug, ToBytes, FromBytes)]
pub struct PeerCertificate {
    pub(crate) cert: UnsignedPeerCertificate,
    pub(crate) signature: Signature,
}

bitflags! {
    /// A set of all capabilities supported by a peer on the network
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PeerCapabilities: u16 {

    }
}

impl ToBytes for PeerCapabilities {
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        self.bits().encode(buf)
    }
    fn size_hint(&self) -> usize {
        self.bits().size_hint()
    }
}
impl FromBytes<'_> for PeerCapabilities {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let mask = u16::decode(reader)?;
        Ok(Self::from_bits_truncate(mask))
    }
}
