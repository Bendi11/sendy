use std::pin::Pin;

use async_stream::{stream, try_stream};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::{Utc, DateTime};
use futures::{Stream, TryStreamExt, StreamExt, stream::BoxStream};
use rsa::pkcs1v15::Signature;
use signature::Verifier;
use sqlx::{Row, QueryBuilder, Sqlite};

use crate::{model::cert::{PeerCertificate, UnsignedPeerCertificate}, FromBytesError, Context, FromBytes, ToBytes, ser::ByteWriter};

use super::{Resource, ResourceKind, ResourceId};

/// A query that may be submitted to lookup a peer's certificate
#[derive(Debug, Clone, Copy)]
pub enum PeerCertificateQuery {
    /// Lookup the certificate of a peer by their public-key fingerprint
    Fingerprint(PeerCertificateId),
    /// Lookup a number of certificates of a peer by the published datetime of their certificate
    Datetime(DateTime<Utc>),
}

pub type PeerCertificateId = ResourceId<PeerCertificate>;

#[async_trait]
impl Resource for PeerCertificate {
    const RESOURCE_KIND: ResourceKind = ResourceKind::Certificate;

    type Query = PeerCertificateQuery;
    type QueryError = PeerCertificateQueryError;
    type HandleError = PeerCertificateHandleError;

    /// Get or generate the ID of the given resource
    fn id(&self) -> ResourceId<Self> {
        ResourceId::new([0 ; 32])
    }
    
    /// Handle the reception of a new instance of this resource, performing all needed validation
    /// and potentially inserting a new value into the [Context]'s database.
    ///
    /// Must return a handle to the inserted resource
    async fn handle(ctx: &Context, bytes: Bytes) -> Result<ResourceId<Self>, Self::HandleError> {
        let ((cert_bytes, cert), signature) = untrusted::Input::from(&bytes)
            .read_all(
                FromBytesError::ExtraBytes,
                |mut rdr| {
                    let (bytes, cert) = UnsignedPeerCertificate::partial_decode(&mut rdr)?;
                    let signature = Signature::decode(&mut rdr)?;

                    Ok(((bytes, cert), signature))
                }
            )?;
                
        let now = Utc::now();

        match cert.timestamp <= now {
            true => match cert.timestamp + cert.ttl >= now {
                true => match cert.keychain.verification.verify(cert_bytes.as_slice_less_safe(), &signature) {
                    Ok(_) => {
                        let fingerprint = &cert.keychain.fingerprint() as &[u8];
                        let ttl = cert.ttl.num_seconds();
                        let data = bytes.as_ref();
                        sqlx::query!(
                            "insert into certificates (userid, creation_timestamp, ttl, data) values (?, ?, ?, ?);",
                            fingerprint,
                            cert.timestamp,
                            ttl,
                            data,
                        ).execute(&ctx.db).await;

                        Ok(ResourceId::new([0 ; 32]))
                    },
                    Err(e) => Err(PeerCertificateHandleError::InvalidSignature(e).into()),
                },
                false => Err(PeerCertificateHandleError::Expired.into()),
            },
            false => Err(PeerCertificateHandleError::InvalidTimestamp(cert.timestamp).into()),
        }
    }
    
    /// Store a new instance of [Self] into the [Context]'s database, returning a handle to the
    /// inserted resource
    async fn store(ctx: &Context, val: Self) -> Result<ResourceId<Self>, Self::HandleError> {
        let fingerprint = val.cert.keychain.fingerprint();
        
        {
            let fingerprint = &fingerprint as &[u8];
            let ttl = val.cert.ttl.num_seconds();
            let data = val.encode_to_vec();
            sqlx::query!(
                "insert into certificates (userid, creation_timestamp, ttl, data) values (?, ?, ?, ?);",
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
    fn query_bytes<'c>(ctx: &'c Context, query: Self::Query) -> BoxStream<'c, Result<Vec<u8>, Self::QueryError>> {
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
    fn query_ids<'c>(ctx: &'c Context, query: Self::Query) -> BoxStream<'c, Result<PeerCertificateId, Self::QueryError>> {
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
    async fn fetch_bytes(ctx: &Context, id: PeerCertificateId) -> Result<Vec<u8>, Self::QueryError> {
        sqlx::query!(r#"select data from certificates where userid=?"#, id)
            .map(|v| v.data)
            .fetch_one(&ctx.db)
            .await
            .map_err(Into::into)
    }
}


#[derive(Debug, thiserror::Error)]
pub enum PeerCertificateQueryError {
    #[error("Failed to decode a certificate from database: {0}")]
    Decode(#[from] FromBytesError),
    #[error("Failed to execute database operation: {0}")]
    Sql(#[from] sqlx::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum PeerCertificateHandleError {
    #[error("Failed to execute database operation: {0}")]
    Sql(#[from] sqlx::Error),
    #[error("Failed to decode a certificate from received bytes: {0}")]
    Decode(#[from] FromBytesError),
    #[error("Signature of self-signed certificate was invalid: {0}")]
    InvalidSignature(#[from] signature::Error),
    #[error("Invalid certificate timestamp {0} is in the future")]
    InvalidTimestamp(chrono::DateTime<Utc>),
    #[error("Certificate TTL has expired")]
    Expired,
}

impl PeerCertificateQuery {
    /// Get the tag to encode to bytes marking what kind of query this is
    const fn tag(&self) -> u8 {
        match self {
            Self::Fingerprint(_) => 1,
            Self::Datetime(_) => 2,
        }
    }
    
    /// Append an SQL condition to the given query builder that will filter results to match the
    /// query
    pub(crate) fn sql<'a, 'b>(self, query: &'a mut QueryBuilder<'b, Sqlite>) -> &'a mut QueryBuilder<'b, Sqlite> {
        match self {
            Self::Fingerprint(f) => query.push(" where userid= ").push_bind(f),
            Self::Datetime(dt) => query.push(" where creation_timestamp>=").push_bind(dt)
        }
    }
}

impl ToBytes for PeerCertificateQuery {
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), crate::ser::ToBytesError> {
        self.tag().encode(buf);
        match self {
            Self::Fingerprint(f) => f.encode(buf),
            Self::Datetime(dt) => dt.encode(buf),
        }
    }

    fn size_hint(&self) -> usize {
        self.tag().size_hint()
    }
}

impl<'a> FromBytes<'a> for PeerCertificateQuery {
    fn decode(reader: &mut untrusted::Reader<'a>) -> Result<Self, FromBytesError> {
        let tag = u8::decode(reader)?;

        match tag {
            1 => PeerCertificateId::decode(reader).map(Self::Fingerprint),
            2 => DateTime::<Utc>::decode(reader).map(Self::Datetime),
            other => Err(FromBytesError::Parsing(format!("Failed to decode peer certificate query: invalid query tag {:X}", other))),
        }
    }
}
