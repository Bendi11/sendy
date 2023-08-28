//! Model for peer certificates containing identification, authentication, and capabilities

use std::net::IpAddr;

use bitflags::bitflags;
use chrono::{DateTime, Duration, Utc};
use rsa::{pkcs1v15::Signature, signature::SignatureEncoding};

use crate::{FromBytes, ToBytes, ser::{ByteWriter, ToBytesError}, FromBytesError};

use super::crypto::PublicKeychain;

/// A peer's certificate that is meant to fully introduce one peer to another, without the
/// accompanying signature
#[derive(Debug)]
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

pub struct PeerCertificate {
    pub(crate) cert: UnsignedPeerCertificate,
    pub(crate) signature: Signature,
}

bitflags! {
    /// A set of all capabilities supported by a peer on the network
    #[derive(Debug)]
    pub struct PeerCapabilities: u16 {
        
    }
}

impl ToBytes for UnsignedPeerCertificate {
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        self.keychain.encode(buf)?;
        self.capabilities.encode(buf)?;
        self.username.encode(buf)?;
        self.sockaddr.encode(buf)?;
        self.timestamp.encode(buf)?;
        self.ttl.encode(buf)?;

        Ok(())
    }

    fn size_hint(&self) -> usize {
        self.keychain.size_hint() +
        self.capabilities.size_hint() +
        self.username.size_hint() +
        self.sockaddr.size_hint() +
        self.timestamp.size_hint() +
        self.ttl.size_hint()
    }
}
impl FromBytes<'_> for UnsignedPeerCertificate {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let keychain = PublicKeychain::decode(reader)?;
        let capabilities = PeerCapabilities::decode(reader)?;
        let username = String::decode(reader)?;
        let sockaddr = IpAddr::decode(reader)?;
        let timestamp = DateTime::<Utc>::decode(reader)?;
        let ttl = Duration::decode(reader)?;

        Ok(Self {
            keychain,
            capabilities,
            username,
            sockaddr,
            timestamp,
            ttl,
        })
    }
}
impl ToBytes for PeerCertificate {
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        self.cert.encode(buf)?;
        self.signature.encode(buf)?;

        Ok(())
    }

    fn size_hint(&self) -> usize {
        self.cert.size_hint() + self.signature.size_hint()
    }
}
impl FromBytes<'_> for PeerCertificate {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let cert = UnsignedPeerCertificate::decode(reader)?;
        let signature = Signature::decode(reader)?;
        Ok(Self { cert, signature })
    }
}

impl ToBytes for PeerCapabilities {
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> { self.bits().encode(buf) }
    fn size_hint(&self) -> usize { self.bits().size_hint() }
}
impl FromBytes<'_> for PeerCapabilities {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let mask = u16::decode(reader)?;
        Ok(Self::from_bits_truncate(mask))
    }
}

impl ToBytes for Signature {
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        self.to_bytes().as_ref().encode(buf)
    }

    fn size_hint(&self) -> usize {
        self.encoded_len()
    }
}
impl<'a> FromBytes<'a> for Signature {
    fn decode(reader: &mut untrusted::Reader<'a>) -> Result<Self, FromBytesError> {
        let buf = <&[u8]>::decode(reader)?;
        Self::try_from(buf)
            .map_err(|e| FromBytesError::Parsing(format!("Failed to parse encoded signature: {}", e)))
    }
}
