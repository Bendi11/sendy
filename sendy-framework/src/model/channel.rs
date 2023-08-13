use std::fmt;

use argon2::Argon2;
use bytes::BufMut;
use chacha20poly1305::{aead::KeySizeUser, ChaCha20Poly1305};
use digest::{Digest, OutputSizeUser};
use generic_array::GenericArray;
use rand_core::{OsRng, RngCore};
use rsa::rand_core;
use sha2::Sha256;

use crate::{FromBytes, ToBytes};

use super::crypto::SHA256_HASH_LEN_BYTES;

/// A channel identifier created by hashing the [Channel]'s seed
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ChannelId(pub [u8 ; SHA256_HASH_LEN_BYTES]);

/// A key derived from a channel's random seed used to encrypt channel messages
pub type ChannelKey = GenericArray<u8, <ChaCha20Poly1305 as KeySizeUser>::KeySize>;

/// A channel that should only be stored locally, contains the symmetric key that was generated
/// from the transmitted random seed
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct KeyedChannel {
    /// All channel data that does not have to do with the symmetric key
    pub channel: UnkeyedChannel,
    /// Symmetric key generated from the random seed
    pub key: ChannelKey,
}

/// Channel as it is sent to peers, without the generated symmetric key
///
/// Contains some metadata (currently only name) of the channel, the [Context](crate::ctx::Context)
/// is responsible for actually storing messages sent to each channel
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UnkeyedChannel {
    /// ID of the channel, generated from the seed
    pub id: ChannelId,
    /// Randomly generated seed that is hashed to produce the channel ID and put through a KDF to
    /// generate the symmetric channel key
    pub seed: [u8; 32],
    /// Randomly-generated salt used with a KDF to derive the symmetric key
    pub keysalt: [u8; 16],
    /// Name of the channel
    pub name: String,
}

impl UnkeyedChannel {
    /// Derive the symmetric key used to encrypt and decrypt messages from this channel
    pub fn gen_key(self) -> argon2::Result<KeyedChannel> {
        let argon = Argon2::default();

        let mut key = [0u8; 32];
        argon.hash_password_into(&self.seed, &self.keysalt, &mut key)?;

        Ok(KeyedChannel {
            channel: self,
            key: key.into(),
        })
    }

    /// Create a new channel, randomly generating the seed and symmetric key salts and hashing a
    /// [ChannelId]
    pub fn new(name: String) -> Self {
        let mut rng = OsRng;

        let mut seed = [0u8; 32];
        let mut keysalt = [0u8; 16];
        rng.fill_bytes(&mut seed);
        rng.fill_bytes(&mut keysalt);

        let id = ChannelId::hash(&seed);

        Self {
            id,
            seed,
            keysalt,
            name,
        }
    }
}

impl ChannelId {
    /// Hash the given seed to produce a new channel ID
    fn hash(seed: &[u8; 32]) -> Self {
        let mut hash = Sha256::new();
        hash.update(&seed);

        Self(hash.finalize().into())
    }
}

/// Format:
/// ID - [ChannelId]
/// seed - 32 bytes - seed that can be hased to the channel ID
/// salt - 16 bytes - salt appended to the seed used to derive the symmetric key
/// name - [String]
impl ToBytes for UnkeyedChannel {
    fn write<W: BufMut>(&self, mut buf: W) {
        self.id.write(&mut buf);
        self.seed.write(&mut buf);
        self.keysalt.write(&mut buf);
        self.name.write(&mut buf);
    }

    fn size_hint(&self) -> Option<usize> {
        self.id
            .size_hint()
            .and_then(|sz| self.seed.size_hint().map(|s| s + sz))
            .and_then(|sz| self.keysalt.size_hint().map(|s| s + sz))
            .and_then(|sz| self.name.size_hint().map(|s| s + sz))
    }
}

impl FromBytes for UnkeyedChannel {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, crate::FromBytesError> {
        let id = ChannelId::parse(reader)?;
        let seed = <[u8; 32]>::parse(reader)?;
        let keysalt = <[u8; 16]>::parse(reader)?;
        let name = String::parse(reader)?;

        Ok(Self {
            id,
            seed,
            keysalt,
            name,
        })
    }
}

/// Format:
/// ID - 8 bytes - little endian
impl ToBytes for ChannelId {
    fn write<W: BufMut>(&self, mut buf: W) {
        self.0.write(buf)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.0.len())
    }
}

impl FromBytes for ChannelId {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, crate::FromBytesError> {
        let id = <[u8 ; 32]>::parse(reader)?;
        Ok(Self(id))
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x?}", &self.0)
    }
}
