//! Traits modelling a generic interface that all resources persisted by the network must conform
//! to

use std::{fmt, hash::Hash, marker::PhantomData, sync::Arc};

use crate::{model::{crypto::SHA256_HASH_LEN, cert::PeerCertificate, channel::Channel}, Context, FromBytes, FromBytesError, ToBytes};
use async_stream::try_stream;
use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use futures::stream::BoxStream;
use sendy_wireformat::ToBytesError;
use sqlx::{Decode, Encode, Sqlite};

pub use self::cert::PeerCertificateManager;
pub use self::channel::ChannelManager;

pub mod cert;
pub mod channel;

/// State required for resources to be persisted in a database
#[derive(Debug,)]
pub struct Resources {
    pub certificate: PeerCertificateManager,
    pub channel: ChannelManager,
}

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

pub trait Resource {
    type Manager: ResourceManager;
}

/// Resources are any data meant to be persisted on the sendy network, they must be signed by an
/// author and identifiable by a unique ID
#[async_trait]
pub trait ResourceManager: Sized {
    /// Tag that can identify the kind of resource this is for generic resource IDs
    const RESOURCE_KIND: ResourceKind;
    
    /// The resource type that is managed by `Self`
    type Resource: ToBytes + for<'a> FromBytes<'a> + Resource;

    /// Associated type that is used to query other nodes for this resource
    type Query: ToBytes + FromBytes<'static> + Send;

    /// Get or generate the ID of the given resource
    fn id(&self, res: &Self::Resource) -> Result<ResourceId<Self::Resource>, ResourceError>;

    /// Handle the reception of a new instance of this resource, performing all needed validation
    /// and potentially inserting a new value into the [Context]'s database.
    ///
    /// Must return a handle to the inserted resource
    async fn handle(&self, ctx: &Context, bytes: Bytes) -> Result<ResourceId<Self::Resource>, ResourceError>;

    /// Store a new instance of [Self] into the [Context]'s database, returning a handle to the
    /// inserted resource
    async fn store(&self, ctx: &Context, val: Self::Resource) -> Result<ResourceId<Self::Resource>, ResourceError>;

    /// Generate and execute an SQL query that will return records that match the given
    /// [Query](Self::Query)
    fn query_bytes<'c>(
        &self,
        ctx: &'c Context,
        query: Self::Query,
    ) -> BoxStream<'c, Result<Vec<u8>, ResourceError>>;

    /// Generate and execute an SQL query that will return the resource IDs of records that match the given
    /// [Query](Self::Query)
    fn query_ids<'c>(
        &self,
        ctx: &'c Context,
        query: Self::Query,
    ) -> BoxStream<'c, Result<ResourceId<Self::Resource>, ResourceError>>;

    /// Fetch the bytes that can be decoded to an instance of this resource type
    async fn fetch_bytes(&self, ctx: &Context, id: ResourceId<Self::Resource>) -> Result<Option<Vec<u8>>, ResourceError>;

    /// Query the database using the given [Query](Self::Query) type, and decode each result to an
    /// instance of [Self]
    fn query<'c>(
        &self,
        ctx: &'c Context,
        query: Self::Query,
    ) -> BoxStream<'c, Result<Self::Resource, ResourceError>>
    where
        Self: Send + Sync,
        Self::Resource: Send + Sync,
    {
        Box::pin(try_stream! {
            let query = self.query_bytes(ctx, query);

            for await instance in query {
                yield Self::Resource::decode_from_slice(&instance?)?;
            }
        })
    }

    /// Fetch and decode an instance of `Self` by the given resource ID
    async fn fetch(&self, ctx: &Context, id: ResourceId<Self::Resource>) -> Result<Option<Self::Resource>, ResourceError>
    where
        Self: Send + Sync,
        Self::Resource: Send + Sync
    {
        let bytes = self.fetch_bytes(ctx, id).await?;
        match bytes {
            Some(bytes) => Self::Resource::decode_from_slice(&bytes)
                .map(Some)
                .map_err(Into::into),
            None => Ok(None)
        }
    }
}

impl<R: Resource> ResourceId<R> {
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
        struct ShortId<'a, R: Resource>(&'a ResourceId<R>);

        impl<'a, R: Resource> fmt::Display for ShortId<'a, R> {
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

impl<R: Resource> ToBytes for ResourceId<R> {
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

impl<R: Resource> fmt::Debug for ResourceId<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.hash.fmt(f)
    }
}

impl<R: Resource> Clone for ResourceId<R> {
    fn clone(&self) -> Self {
        Self {
            hash: self.hash,
            boo: PhantomData,
        }
    }
}
impl<R: Resource> Copy for ResourceId<R> {}

impl<'s, R: Resource> Encode<'s, Sqlite> for ResourceId<R> {
    fn encode_by_ref(
        &self,
        buf: &mut <Sqlite as sqlx::database::HasArguments<'s>>::ArgumentBuffer,
    ) -> sqlx::encode::IsNull {
        <Vec<u8> as Encode<'s, Sqlite>>::encode(self.hash.to_vec(), buf)
    }
}
impl<R: Resource> sqlx::Type<Sqlite> for ResourceId<R> {
    fn type_info() -> <Sqlite as sqlx::Database>::TypeInfo {
        <[u8] as sqlx::Type<Sqlite>>::type_info()
    }
}
impl<'s, R: Resource> Decode<'s, Sqlite> for ResourceId<R> {
    fn decode(
        value: <Sqlite as sqlx::database::HasValueRef<'s>>::ValueRef,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let me = <&'s [u8] as Decode<'s, Sqlite>>::decode(value)
            .map(|buf| <[u8; SHA256_HASH_LEN]>::try_from(buf).map(Self::new))??;

        Ok(me)
    }
}

impl<R: Resource> Hash for ResourceId<R> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state)
    }
}
impl<R: Resource> std::cmp::PartialEq for ResourceId<R> {
    fn eq(&self, other: &Self) -> bool {
        self.hash.eq(&other.hash)
    }
}
impl<R: Resource> std::cmp::Eq for ResourceId<R> {}

impl<R: Resource> fmt::LowerHex for ResourceId<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.hash {
            write!(f, "{:x}", byte)?;
        }

        Ok(())
    }
}
impl<R: Resource> fmt::UpperHex for ResourceId<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.hash {
            write!(f, "{:X}", byte)?
        }

        Ok(())
    }
}
