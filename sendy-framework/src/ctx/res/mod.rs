//! Traits modelling a generic interface that all resources persisted by the network must conform
//! to

use std::{fmt, hash::Hash, marker::PhantomData};

use crate::{model::{crypto::SHA256_HASH_LEN, cert::PeerCertificate}, FromBytes, FromBytesError, ToBytes};
use chrono::Utc;
use sendy_wireformat::ToBytesError;
use sqlx::{Decode, Encode, Sqlite};

pub mod cert;
pub mod channel;

/// Tag that can identify the kind of resource that a generic resource ID is referencing
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, ToBytes, FromBytes)]
pub enum ResourceKind {
    /// A signed certificate that validates a peer
    Certificate = 0,
    /// A channel record signed by the channel owner
    Channel = 1,
}

/// A 32-byte ID that uniquely identifies a resource by the hash of its contents
pub struct ResourceId<R> {
    hash: [u8; SHA256_HASH_LEN],
    boo: PhantomData<R>,
}

/// Any error that may occur when operating with a resource in a database
#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Failed to decode a value from bytes: {0}")]
    Decode(#[from] FromBytesError),
    #[error("Failed to encode a value to bytes: {0}")]
    Encode(#[from] ToBytesError),
    #[error("Failed to execute database operation: {0}")]
    Sql(#[from] sqlx::Error),
    #[error("Invalid signature: {0}")]
    InvalidSignature(#[from] signature::Error),
    #[error("Invalid certificate timestamp of resource: {0}")]
    InvalidTimestamp(chrono::DateTime<Utc>),
    #[error("Resource TTL has expired")]
    Expired,
    #[error("Unknown certificate ID {0:X}")]
    UnknownCertificate(ResourceId<PeerCertificate>),
}

impl<R> ResourceId<R> {
    /// Create a new resource identifier by a hash of the resource's contents
    pub const fn new(hash: [u8; 32]) -> Self {
        Self {
            hash,
            boo: PhantomData,
        }
    }

    /// Get a short version (last 4 least significant bytes) of this resource ID to be used for display in log messages
    #[inline(always)]
    pub const fn short<'a>(&'a self) -> impl fmt::Display + 'a {
        struct ShortId<'a, R>(&'a ResourceId<R>);

        impl<'a, R> fmt::Display for ShortId<'a, R> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in &self.0.hash[28..] {
                    write!(f, "{:x}", byte)?
                }

                Ok(())
            }
        }

        ShortId(self)
    }
}

impl<R> ToBytes for ResourceId<R> {
    fn encode<W: crate::ByteWriter>(&self, buf: &mut W) -> Result<(), crate::ToBytesError> {
        self.hash.encode(buf)
    }

    fn size_hint(&self) -> usize {
        self.hash.size_hint()
    }
}
impl<R: 'static> FromBytes<'_> for ResourceId<R> {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        <[u8; 32]>::decode(reader).map(|hash| Self {
            hash,
            boo: PhantomData,
        })
    }
}

impl<R> fmt::Debug for ResourceId<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.hash.fmt(f)
    }
}

impl<R> Clone for ResourceId<R> {
    fn clone(&self) -> Self {
        Self {
            hash: self.hash,
            boo: PhantomData,
        }
    }
}
impl<R> Copy for ResourceId<R> {}

impl<'s, R> Encode<'s, Sqlite> for ResourceId<R> {
    fn encode_by_ref(
        &self,
        buf: &mut <Sqlite as sqlx::database::HasArguments<'s>>::ArgumentBuffer,
    ) -> sqlx::encode::IsNull {
        <Vec<u8> as Encode<'s, Sqlite>>::encode(self.hash.to_vec(), buf)
    }
}
impl<R> sqlx::Type<Sqlite> for ResourceId<R> {
    fn type_info() -> <Sqlite as sqlx::Database>::TypeInfo {
        <[u8] as sqlx::Type<Sqlite>>::type_info()
    }
}
impl<'s, R> Decode<'s, Sqlite> for ResourceId<R> {
    fn decode(
        value: <Sqlite as sqlx::database::HasValueRef<'s>>::ValueRef,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let me = <&'s [u8] as Decode<'s, Sqlite>>::decode(value)
            .map(|buf| <[u8; SHA256_HASH_LEN]>::try_from(buf).map(Self::new))??;

        Ok(me)
    }
}

impl<R> Hash for ResourceId<R> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state)
    }
}
impl<R> std::cmp::PartialEq for ResourceId<R> {
    fn eq(&self, other: &Self) -> bool {
        self.hash.eq(&other.hash)
    }
}
impl<R> std::cmp::Eq for ResourceId<R> {}

impl<R> fmt::LowerHex for ResourceId<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.hash {
            write!(f, "{:x}", byte)?;
        }

        Ok(())
    }
}
impl<R> fmt::UpperHex for ResourceId<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.hash {
            write!(f, "{:X}", byte)?
        }

        Ok(())
    }
}
