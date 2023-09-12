use async_stream::try_stream;
use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::stream::BoxStream;
use rsa::{pkcs1v15::Signature, signature::Verifier};
use sendy_wireformat::{ToBytes, FromBytes, FromBytesError};
use sqlx::Executor;

use crate::{model::{channel::Channel, cert::PeerCertificate}, Context};

use super::{ResourceManager, ResourceKind, ResourceId, ResourceError, Resource, cert::PeerCertificateId};

/// A query for channel records
#[repr(u8)]
#[derive(Debug, ToBytes, FromBytes)]
pub enum ChannelQuery {
    /// Querying for a channel record by ID
    Id(ResourceId<Channel>) = 0,
    /// Querying for channel owner ID
    Owner(PeerCertificateId) = 1,
    /// Querying for channels by the creation timestamp of the channel
    Timestamp(DateTime<Utc>) = 2,
}

#[derive(Debug,)]
pub struct ChannelManager {

}

pub type ChannelId = ResourceId<Channel>;

impl Resource for Channel {
    type Manager = ChannelManager;
}

#[async_trait]
impl ResourceManager for ChannelManager {
    const RESOURCE_KIND: ResourceKind = ResourceKind::Channel;

    /// Associated type that is used to query other nodes for this resource
    type Query = ChannelQuery;

    type Resource = Channel;

    /// Get or generate the ID of the given resource
    fn id(&self, res: &Self::Resource) -> Result<ResourceId<Self::Resource>, ResourceError> {
        Ok(res.id)
    }

    /// Handle the reception of a new instance of this resource, performing all needed validation
    /// and potentially inserting a new value into the [Context]'s database.
    ///
    /// Must return a handle to the inserted resource
    async fn handle(&self, ctx: &Context, bytes: Bytes) -> Result<ResourceId<Self::Resource>, ResourceError> {
        let reader = untrusted::Input::from(&bytes);
        let (bytes, channel, signature) = reader
            .read_all(FromBytesError::ExtraBytes, |rdr| {
                let (bytes, channel) = Channel::partial_decode(rdr)?;
                let signature = Signature::decode(rdr)?;

                Ok((bytes, channel, signature))
            })?;

        let record = sqlx::query!("select idx, data from certificates where userid=?", channel.owner)
            .fetch_one(&ctx.db)
            .await?;

        let (idx, signed) = (
            record.idx,
            PeerCertificate::decode_from_slice(&record.data)?
        );
        
        signed
            .cert
            .keychain
            .verification
            .verify(bytes.as_slice_less_safe(), &signature)
            .map_err(|e| ResourceError::InvalidSignature(e))?;

        {
            let channelid = channel.id;
            let last_update = channel.last_update;
            ctx.db.execute(
                sqlx::query!(
                    "insert into channels (channelid, last_update, owneridx) values (?, ?, ?)",
                    channelid,
                    last_update,
                    idx
                )
            ).await?;
        }

        Ok(channel.id)
    }

    /// Store a new instance of [Self] into the [Context]'s database, returning a handle to the
    /// inserted resource
    async fn store(&self, ctx: &Context, val: Self::Resource) -> Result<ResourceId<Self::Resource>, ResourceError> {

    }

    /// Generate and execute an SQL query that will return records that match the given
    /// [Query](Self::Query)
    fn query_bytes<'c>(
        &self,
        ctx: &'c Context,
        query: Self::Query,
    ) -> BoxStream<'c, Result<Vec<u8>, ResourceError>> {
        
    }

    /// Generate and execute an SQL query that will return the resource IDs of records that match the given
    /// [Query](Self::Query)
    fn query_ids<'c>(
        &self,
        ctx: &'c Context,
        query: Self::Query,
    ) -> BoxStream<'c, Result<ResourceId<Self::Resource>, ResourceError>> {

    }

    /// Fetch the bytes that can be decoded to an instance of this resource type
    async fn fetch_bytes(&self, ctx: &Context, id: ResourceId<Self::Resource>) -> Result<Vec<u8>, ResourceError> {

    }
}
