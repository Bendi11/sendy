///! Cryptographic data that facilitates authentication and encryption between peers and across
///! channels
use digest::Digest;

use rsa::{
    pkcs1v15::{SigningKey, VerifyingKey},
    RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;

use crate::{FromBytes, ToBytes, ToBytesError};

/// Length of an SHA256 hash in bytes
pub const SHA256_HASH_LEN: usize = 32;

/// Public authentication and encryption keys
#[derive(Clone, Debug, ToBytes, FromBytes)]
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
            verification: RsaPrivateKey::from(self.authentication.clone())
                .to_public_key()
                .into(),
            encryption: self.decryption.to_public_key(),
        }
    }
}

impl PublicKeychain {
    /// Calculate the fingerprint of the public authentication key by applying the sha256 hash
    /// function to it
    pub fn fingerprint(&self) -> Result<[u8; SHA256_HASH_LEN], ToBytesError> {
        let mut hash = Sha256::new();

        hash.update(self.verification.encode_to_vec()?);

        Ok(hash.finalize().into())
    }
}
