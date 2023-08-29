use crate::{ToBytes, ByteWriter, ToBytesError, FromBytes, FromBytesError};
use rsa::sha2::Sha256;
use rsa::{pkcs1v15::Signature, signature::SignatureEncoding};
use rsa::{
    pkcs1v15::{SigningKey, VerifyingKey},
    pkcs8::{der::Decode, EncodePrivateKey, EncodePublicKey, DecodePublicKey, PrivateKeyInfo},
    RsaPrivateKey, RsaPublicKey,
};


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
        let bytes = <&[u8] as FromBytes<'_>>::decode(reader)?;
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
