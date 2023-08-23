//! Model for peer certificates containing identification, authentication, and capabilities

use std::net::IpAddr;

use bitflags::bitflags;
use rsa::pkcs1v15::Signature;

use crate::{FromBytes, ToBytes, ser::{ByteWriter, ToBytesError}};

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
}

pub struct PeerCertificate {
    cert: UnsignedPeerCertificate,
    signature: Signature,
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

        Ok(())
    }

    fn size_hint(&self) -> usize {
        self.keychain.size_hint() +
        self.capabilities.size_hint() +
        self.username.size_hint() +
        self.sockaddr.size_hint()
    }
}
impl FromBytes<'_> for UnsignedPeerCertificate {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, crate::FromBytesError> {
        let keychain = PublicKeychain::decode(reader)?;
        let capabilities = PeerCapabilities::decode(reader)?;
        let username = String::decode(reader)?;
        let sockaddr = IpAddr::decode(reader)?;

        Ok(Self {
            keychain,
            capabilities,
            username,
            sockaddr,
        })
    }
}


impl ToBytes for PeerCapabilities {
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> { self.bits().encode(buf) }
    fn size_hint(&self) -> usize { self.bits().size_hint() }
}
impl FromBytes<'_> for PeerCapabilities {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, crate::FromBytesError> {
        let mask = u16::decode(reader)?;
        Ok(Self::from_bits_truncate(mask))
    }
}
