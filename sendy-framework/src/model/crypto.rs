///! Cryptographic data that facilitates authentication and encryption between peers and across
///! channels


use digest::Digest;

use rsa::{
    pkcs1v15::{SigningKey, VerifyingKey},
    pkcs8::{der::Decode, EncodePrivateKey, EncodePublicKey, DecodePublicKey, PrivateKeyInfo},
    RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;

use crate::{
    ser::{ByteWriter, ToBytesError},
    FromBytes, FromBytesError, ToBytes,
};

/// Length of an SHA256 hash in bytes
pub const SHA256_HASH_LEN: usize = 32;

/// Public authentication and encryption keys
#[derive(Clone, Debug)]
pub struct PublicKeychain {
    /// Key used to verify message signatures
    pub verification: VerifyingKey<Sha256>,
    /// Key used to send or store encrypted messages for a peer
    pub encryption: RsaPublicKey,
}

/// Private keys used to authenticate and exhcange symmetric encryption keys
#[derive(Debug)]
pub struct PrivateKeychain {
    /// Key used to sign messages to verify the authenticity of a resource
    pub authentication: SigningKey<Sha256>,
    /// Key used to decrypt private messages
    pub decryption: RsaPrivateKey,
}

impl PrivateKeychain {
    /// Create a new private keychain from private authentication and encryption keys
    pub const fn new(authentication: SigningKey<Sha256>, decryption: RsaPrivateKey) -> Self {
        Self {
            authentication,
            decryption,
        }
    }
    
    /// Calculate the public keychain that corresponds to this private keychain
    pub fn public(&self) -> PublicKeychain {
        PublicKeychain {
            verification: RsaPrivateKey::from(self.authentication.clone()).to_public_key().into(),
            encryption: self.decryption.to_public_key()
        }
    }
}

impl PublicKeychain {
    /// Calculate the fingerprint of the public authentication key by applying the sha256 hash
    /// function to it 
    pub fn fingerprint(&self) -> Result<[u8 ; SHA256_HASH_LEN], ToBytesError> {
        let mut hash = Sha256::new();

        hash.update(self.verification.encode_to_vec()?);

        Ok(hash.finalize().into())
    }
}

impl ToBytes for PublicKeychain {
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        self.verification.encode(buf)?;
        self.encryption.encode(buf)?;
        Ok(())
    }

    fn size_hint(&self) -> usize {
        self.verification.size_hint() + self.encryption.size_hint()
    }
}
impl FromBytes<'_> for PublicKeychain {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let verification = RsaPublicKey::decode(reader)?;
        let encryption = RsaPublicKey::decode(reader)?;
        Ok(Self {
            verification: verification.into(),
            encryption,
        })
    }
}

impl ToBytes for VerifyingKey<Sha256> {
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        self.as_ref().encode(buf)
    }
}

/// Format: same as Vec<u8>, body is DER encoded key material
impl ToBytes for RsaPublicKey {
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        let der = self
            .to_public_key_der()
            .map_err(|e| ToBytesError::InvalidValue(format!("Invalid RSA public key: {}", e)))?;
        
        der.as_bytes().encode(buf)
    }
}
impl FromBytes<'_> for RsaPublicKey {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let bytes = <&[u8] as FromBytes>::decode(reader)?;
        RsaPublicKey::from_public_key_der(bytes)
            .map_err(|e| FromBytesError::Parsing(format!("Failed to read public key DER: {}", e)))
    }
}

impl ToBytes for RsaPrivateKey {
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        let der = self.to_pkcs8_der().map_err(|e| {
            ToBytesError::InvalidValue(format!("Failed to encode private key as DER: {}", e))
        })?;
        
        der.as_bytes().encode(buf)
    }
}
impl FromBytes<'_> for RsaPrivateKey {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let bytes = <&[u8] as FromBytes>::decode(reader)?;
        RsaPrivateKey::try_from(
            PrivateKeyInfo::from_der(&bytes)
                .map_err(|e| FromBytesError::Parsing(format!("Failed to decode DER: {}", e)))?,
        )
        .map_err(|e| {
            FromBytesError::Parsing(format!(
                "Failed to read private key from decoded DER: {}",
                e
            ))
        })
    }
}
