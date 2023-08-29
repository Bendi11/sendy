use async_stream::try_stream;
use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::stream::BoxStream;
use sendy_wireformat::{ToBytes, FromBytes};

use crate::{model::channel::Channel, Context};

use super::{Resource, ResourceKind, ResourceId, ResourceError};

/// A query for channel records
#[repr(u8)]
#[derive(Debug, ToBytes, FromBytes)]
pub enum ChannelQuery {
    /// Querying for a channel record by ID
    Id(ResourceId<Channel>) = 0,
    /// Querying for channels by the creation timestamp of the channel
    Timestamp(DateTime<Utc>) = 1,
}

#[async_trait]
impl Resource for Channel {
    const RESOURCE_KIND: ResourceKind = ResourceKind::Channel;

    /// Associated type that is used to query other nodes for this resource
    type Query = ChannelQuery;

    /// Get or generate the ID of the given resource
    fn id(&self) -> Result<ResourceId<Self>, ResourceError> {
        Ok(self.id)
    }

    /// Handle the reception of a new instance of this resource, performing all needed validation
    /// and potentially inserting a new value into the [Context]'s database.
    ///
    /// Must return a handle to the inserted resource
    async fn handle(ctx: &Context, bytes: Bytes) -> Result<ResourceId<Self>, ResourceError> {

    }

    /// Store a new instance of [Self] into the [Context]'s database, returning a handle to the
    /// inserted resource
    async fn store(ctx: &Context, val: Self) -> Result<ResourceId<Self>, ResourceError> {

    }

    /// Generate and execute an SQL query that will return records that match the given
    /// [Query](Self::Query)
    fn query_bytes<'c>(
        ctx: &'c Context,
        query: Self::Query,
    ) -> BoxStream<'c, Result<Vec<u8>, ResourceError>> {

    }

    /// Generate and execute an SQL query that will return the resource IDs of records that match the given
    /// [Query](Self::Query)
    fn query_ids<'c>(
        ctx: &'c Context,
        query: Self::Query,
    ) -> BoxStream<'c, Result<ResourceId<Self>, ResourceError>> {

    }

    /// Fetch the bytes that can be decoded to an instance of this resource type
    async fn fetch_bytes(ctx: &Context, id: ResourceId<Self>) -> Result<Vec<u8>, ResourceError> {

    }
}
