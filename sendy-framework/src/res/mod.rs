//! Traits modelling a generic interface that all resources persisted by the network must conform
//! to

use std::{marker::PhantomData, pin::Pin, fmt};

use crate::{ToBytes, FromBytes, Context, FromBytesError, model::crypto::SHA256_HASH_LEN};
use async_trait::async_trait;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use sqlx::{Sqlite, Encode, Decode};

mod cert;

/// Tag that can identify the kind of resource that a generic resource ID is referencing
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    /// A signed certificate that validates a peer
    Certificate,
}

/// A 32-byte ID that uniquely identifies a resource by the hash of its contents
pub struct ResourceId<'a, R: Resource<'a>> {
    hash: [u8 ; 32],
    boo: PhantomData<&'a R>,
}

/// Resources are any data meant to be persisted on the sendy network, they must be signed by an
/// author and identifiable by a unique ID
#[async_trait]
pub trait Resource<'a>: ToBytes + FromBytes<'a> {
    /// Tag that can identify the kind of resource this is for generic resource IDs
    const RESOURCE_KIND: ResourceKind;

    /// Associated type that is used to query other nodes for this resource
    type Query: ToBytes + FromBytes<'a> + Send;
    
    /// Errors that may occur when handling the reception of a new instance of this resource
    type HandleError: std::error::Error;
    /// Errors that may occur when querying / decoding resources from the database
    type QueryError: std::error::Error + From<FromBytesError>;
    
    /// Get or generate the ID of the given resource
    fn id(&self) -> ResourceId<'a, Self>;
    
    /// Handle the reception of a new instance of this resource, performing all needed validation
    /// and potentially inserting a new value into the [Context]'s database.
    ///
    /// Must return a handle to the inserted resource
    async fn handle(ctx: &Context, bytes: Bytes) -> Result<ResourceId<'a, Self>, Self::HandleError>;
    
    /// Store a new instance of [Self] into the [Context]'s database, returning a handle to the
    /// inserted resource
    async fn store(ctx: &Context, val: Self) -> Result<ResourceId<'a, Self>, Self::HandleError>;
    
    /// Generate and execute an SQL query that will return records that match the given
    /// [Query](Self::Query)
    async fn query_bytes<'c>(ctx: &'c Context, query: Self::Query) -> Pin<Box<dyn Stream<Item = Result<&'c [u8], Self::QueryError>>>>;

    /// Generate and execute an SQL query that will return the resource IDs of records that match the given
    /// [Query](Self::Query)
    async fn query_ids(ctx: &Context, query: Self::Query) -> Pin<Box<dyn Stream<Item = Result<ResourceId<'a, Self>, Self::QueryError>>>>;
    
    /// Fetch the bytes that can be decoded to an instance of this resource type
    async fn fetch_bytes<'c>(ctx: &'c Context, id: ResourceId<'a, Self>) -> Result<&'c [u8], Self::QueryError>;
    
    /// Query the database using the given [Query](Self::Query) type, and decode each result to an
    /// instance of [Self]
    async fn query(ctx: &'a Context, query: Self::Query) -> Pin<Box<dyn Stream<Item = Result<Self, Self::QueryError>> + 'a>> {
        Box::pin(
            Self::query_bytes(ctx, query)
                .await
                .map(|bytes| match bytes.map(|bytes| Self::decode_from_slice(bytes).map_err(Into::into)) {
                    Ok(v) => v,
                    Err(e) => Err(e)
                })
        )
    }
    
    /// Fetch and decode an instance of `Self` by the given resource ID
    async fn fetch(ctx: &'a Context, id: ResourceId<'a, Self>) -> Result<Self, Self::QueryError>
    where Self: Sync {
        Self::decode_from_slice(Self::fetch_bytes(ctx, id).await?).map_err(Into::into)
    }
}

impl<'a, R: Resource<'a>> ResourceId<'a, R> {
    /// Create a new resource identifier by a hash of the resource's contents
    pub const fn new(hash: [u8 ; 32]) -> Self {
        Self {
            hash,
            boo: PhantomData,
        }
    }
}

impl<'a, R: Resource<'a>> ToBytes for ResourceId<'a, R> {
    fn encode<W: crate::ser::ByteWriter>(&self, buf: &mut W) -> Result<(), crate::ser::ToBytesError> {
        self.hash.encode(buf) 
    }

    fn size_hint(&self) -> usize {
        self.hash.size_hint()
    }
}
impl<'a, R: Resource<'a>> FromBytes<'a> for ResourceId<'a, R> {
    fn decode(reader: &mut untrusted::Reader<'a>) -> Result<Self, FromBytesError> {
        <[u8 ; 32]>::decode(reader).map(|hash| Self { hash, boo: PhantomData })
    }
}

impl<'a, R: Resource<'a>> fmt::Debug for ResourceId<'a, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.hash.fmt(f)
    }
}

impl<'a, R: Resource<'a>> Clone for ResourceId<'a, R> {
    fn clone(&self) -> Self {
        Self {
            hash: self.hash,
            boo: PhantomData,
        }
    }
}

impl<'a, R: Resource<'a>> Copy for ResourceId<'a, R> {}

impl<'a, 's, R: Resource<'a>> Encode<'s, Sqlite> for ResourceId<'a, R> {
    fn encode_by_ref(&self, buf: &mut <Sqlite as sqlx::database::HasArguments<'_>>::ArgumentBuffer) -> sqlx::encode::IsNull {
        <&'s [u8] as Encode<'s, Sqlite>>::encode_by_ref(&(&self.hash as &'s [u8]), buf) 
    }
}
impl<'a, R: Resource<'a>> sqlx::Type<Sqlite> for ResourceId<'a, R> {
    fn type_info() -> <Sqlite as sqlx::Database>::TypeInfo {
        <[u8] as sqlx::Type<Sqlite>>::type_info()
    }
}
impl<'a, 's, R: Resource<'a>> Decode<'s, Sqlite> for ResourceId<'a, R> {
    fn decode(value: <Sqlite as sqlx::database::HasValueRef<'s>>::ValueRef) -> Result<Self, sqlx::error::BoxDynError> {
        let me = <&'s [u8] as Decode<'s, Sqlite>>::decode(value)
            .map(|buf| <[u8 ; SHA256_HASH_LEN]>::try_from(buf).map(Self::new))??;

        Ok(me)
    }
}
