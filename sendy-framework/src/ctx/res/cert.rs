use std::sync::Arc;

use async_stream::try_stream;
use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::stream::BoxStream;
use rsa::pkcs1v15::Signature;
use signature::Verifier;
use sqlx::{QueryBuilder, Row, Sqlite};

use crate::{
    model::cert::{PeerCertificate, UnsignedPeerCertificate},
    Context, FromBytes, FromBytesError, ToBytes,
};

use super::{ResourceManager, ResourceId, ResourceKind, ResourceError, Resource};

/// A query that may be submitted to lookup a peer's certificate
#[derive(Debug, Clone, Copy, FromBytes, ToBytes)]
#[repr(u8)]
pub enum PeerCertificateQuery {
    /// Lookup the certificate of a peer by their public-key fingerprint
    Fingerprint(PeerCertificateId) = 1,
    /// Lookup a number of certificates of a peer by the published datetime of their certificate
    Datetime(DateTime<Utc>) = 2,
}

pub type PeerCertificateId = ResourceId<PeerCertificate>;

#[derive(Debug,)]
pub struct PeerCertificateManager {

}

impl Resource for PeerCertificate {
    type Manager = PeerCertificateManager;
}

#[async_trait]
impl ResourceManager for PeerCertificateManager {
    const RESOURCE_KIND: ResourceKind = ResourceKind::Certificate;

    type Query = PeerCertificateQuery;

    type Resource = PeerCertificate;

    /// Get or generate the ID of the given resource
    fn id(&self, res: &Self::Resource) -> Result<ResourceId<Self::Resource>, ResourceError> {
        Ok(ResourceId::new(res.cert.keychain.fingerprint()?))
    }

    /// Handle the reception of a new instance of this resource, performing all needed validation
    /// and potentially inserting a new value into the [Context]'s database.
    ///
    /// Must return a handle to the inserted resource
    async fn handle(&self, ctx: &Context, bytes: Bytes) -> Result<ResourceId<Self::Resource>, ResourceError> {
        let ((cert_bytes, cert), signature) =
            untrusted::Input::from(&bytes).read_all(FromBytesError::ExtraBytes, |mut rdr| {
                let (bytes, cert) = UnsignedPeerCertificate::partial_decode(&mut rdr)?;
                let signature = Signature::decode(&mut rdr)?;

                Ok(((bytes, cert), signature))
            })?;

        let now = Utc::now();

        match cert.timestamp <= now {
            true => match cert.timestamp + cert.ttl >= now {
                true => match cert
                    .keychain
                    .verification
                    .verify(cert_bytes.as_slice_less_safe(), &signature)
                {
                    Ok(_) => {
                        let fingerprint = cert.keychain.fingerprint()?;

                        {
                            let fingerprint = fingerprint.as_slice();
                            let ttl = cert.ttl.num_seconds();
                            let data = bytes.as_ref();
                            sqlx::query!(
                                "insert into certificates (userid, creation_timestamp, ttl, data) values (?, ?, ?, ?);",
                                fingerprint,
                                cert.timestamp,
                                ttl,
                                data,
                            ).execute(&ctx.db).await?;
                        }

                        Ok(ResourceId::new(fingerprint))
                    }
                    Err(e) => Err(ResourceError::InvalidSignature(e)),
                },
                false => Err(ResourceError::Expired),
            },
            false => Err(ResourceError::InvalidTimestamp(cert.timestamp)),
        }
    }

    /// Store a new instance of [Self] into the [Context]'s database, returning a handle to the
    /// inserted resource
    async fn store(&self, ctx: &Context, val: Self::Resource) -> Result<ResourceId<Self::Resource>, ResourceError> {
        let fingerprint = val.cert.keychain.fingerprint()?;

        {
            let fingerprint = &fingerprint as &[u8];
            let ttl = val.cert.ttl.num_seconds();
            let data = val.encode_to_vec()?;
            sqlx::query!(
                "insert or replace into certificates (userid, creation_timestamp, ttl, data) values (?, ?, ?, ?);",
                fingerprint,
                val.cert.timestamp,
                ttl,
                data,
            ).execute(&ctx.db).await?;
        }

        Ok(ResourceId::new(fingerprint))
    }

    /// Generate and execute an SQL query that will return records that match the given
    /// [Query](Self::Query)
    fn query_bytes<'c>(
        &self,
        ctx: &'c Context,
        query: Self::Query,
    ) -> BoxStream<'c, Result<Vec<u8>, ResourceError>> {
        Box::pin(try_stream! {
            let mut builder = QueryBuilder::new("select data from certificates");
            let query = query.sql(&mut builder).build();
            let query = query.fetch(&ctx.db);

            for await item in query {
                yield item?.try_get(0)?;
            }
        })
    }

    /// Generate and execute an SQL query that will return the resource IDs of records that match the given
    /// [Query](Self::Query)
    fn query_ids<'c>(
        &self,
        ctx: &'c Context,
        query: Self::Query,
    ) -> BoxStream<'c, Result<PeerCertificateId, ResourceError>> {
        Box::pin(try_stream! {
            let mut builder = QueryBuilder::new("select userid from certificates");
            let query = query.sql(&mut builder)
                .build()
                .fetch(&ctx.db);

            for await item in query {
                yield item?.try_get(0)?
            }
        })
    }

    /// Fetch the bytes that can be decoded to an instance of this resource type
    async fn fetch_bytes(
        &self,
        ctx: &Context,
        id: PeerCertificateId,
    ) -> Result<Option<Vec<u8>>, ResourceError> {
        match sqlx::query!(r#"select data from certificates where userid=?"#, id)
            .map(|v| v.data)
            .fetch_one(&ctx.db)
            .await {
                Ok(v) => Ok(Some(v)),
                Err(sqlx::Error::RowNotFound) => Ok(None),
                Err(e) => Err(e.into()),
        }
    }
}


impl PeerCertificateQuery {
    /// Append an SQL condition to the given query builder that will filter results to match the
    /// query
    pub(self) fn sql<'a, 'b>(
        self,
        query: &'a mut QueryBuilder<'b, Sqlite>,
    ) -> &'a mut QueryBuilder<'b, Sqlite> {
        match self {
            Self::Fingerprint(f) => query.push(" where userid= ").push_bind(f),
            Self::Datetime(dt) => query.push(" where creation_timestamp>=").push_bind(dt),
        }
    }
}
