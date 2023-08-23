use rsa::{
    pkcs1v15::{DecryptingKey, EncryptingKey, SigningKey, VerifyingKey},
    pkcs8::{der::Decode, EncodePrivateKey, EncodePublicKey, PrivateKeyInfo},
    RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;

use crate::{
    ser::{ByteWriter, LenType, ToBytesError},
    FromBytes, FromBytesError, ToBytes,
};

/// Public authentication and encryption keys
#[derive(Clone, Debug)]
pub struct PublicKeychain {
    /// Key used to verify message signatures
    pub verification: VerifyingKey<Sha256>,
    /// Key used to send or store encrypted messages for a peer
    pub encryption: EncryptingKey,
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

        (der.as_bytes().len() as LenType).encode(buf)?;
        buf.put_slice(der.as_bytes());
        Ok(())
    }
}

impl ToBytes for RsaPrivateKey {
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        let der = self.to_pkcs8_der().map_err(|e| {
            ToBytesError::InvalidValue(format!("Failed to encode private key as DER: {}", e))
        })?;

        (der.as_bytes().len() as LenType).encode(buf)?;
        buf.put_slice(der.as_bytes());
        Ok(())
    }
}

impl FromBytes for RsaPrivateKey {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let bytes = <Vec<u8> as FromBytes>::decode(reader)?;
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
