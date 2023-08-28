use std::pin::Pin;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{Utc, DateTime};
use futures::{Stream, TryStreamExt, StreamExt};
use rsa::pkcs1v15::Signature;
use signature::Verifier;
use sqlx::Row;

use crate::{model::cert::{PeerCertificate, UnsignedPeerCertificate}, FromBytesError, Context, FromBytes, ToBytes};

use super::{Resource, ResourceKind, ResourceId};

/// A query that may be submitted to lookup a peer's certificate
#[derive(Debug, Clone, Copy)]
pub enum PeerCertificateQuery {
    /// Lookup the certificate of a peer by their public-key fingerprint
    Fingerprint(PeerCertificateId),
    /// Lookup a number of certificates of a peer by the published datetime of their certificate
    Datetime(DateTime<Utc>),
}

pub type PeerCertificateId = ResourceId<'static, PeerCertificate>;

#[async_trait]
impl Resource<'static> for PeerCertificate {
    const RESOURCE_KIND: ResourceKind = ResourceKind::Certificate;

    type Query = PeerCertificateQuery;
    type QueryError = PeerCertificateQueryError;
    type HandleError = PeerCertificateHandleError;

    /// Get or generate the ID of the given resource
    fn id(&self) -> ResourceId<'static, Self> {
        ResourceId::new([0 ; 32])
    }
    
    /// Handle the reception of a new instance of this resource, performing all needed validation
    /// and potentially inserting a new value into the [Context]'s database.
    ///
    /// Must return a handle to the inserted resource
    async fn handle(ctx: &Context, bytes: Bytes) -> Result<ResourceId<'static, Self>, Self::HandleError> {
        let ((cert_bytes, cert), signature) = untrusted::Input::from(&bytes)
            .read_all(
                FromBytesError::ExtraBytes,
                |rdr| {
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
                        let insert = sqlx::query!(
                            "insert into certificates (userid, creation_timestamp, ttl, data) values (?, ?, ?, ?);",
                            &cert.keychain.fingerprint() as &[u8],
                            cert.timestamp,
                            cert.ttl.num_seconds(),
                            bytes.as_ref()
                        ).execute(&ctx.db);

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
    async fn store(ctx: &Context, val: Self) -> Result<ResourceId<'static, Self>, Self::HandleError> {
        let fingerprint = val.cert.keychain.fingerprint();

        sqlx::query!(
            "insert into certificates (userid, creation_timestamp, ttl, data) values (?, ?, ?, ?);",
            &fingerprint as &[u8],
            val.cert.timestamp,
            val.cert.ttl.num_seconds(),
            val.encode_to_vec()
        ).execute(&ctx.db).await?;

        Ok(ResourceId::new(fingerprint))
    }
    
    /// Generate and execute an SQL query that will return records that match the given
    /// [Query](Self::Query)
    async fn query_bytes<'c>(ctx: &'c Context, query: Self::Query) -> Pin<Box<dyn Stream<Item = Result<&'c [u8], Self::QueryError>>>> {
        Box::pin(
            match query {
                PeerCertificateQuery::Fingerprint(userid) => sqlx::query!(r#"select data as "data: &'static [u8]" from certificates where userid=?"#, userid)
                    .map(|v| v.data)
                    .fetch(&ctx.db),
                PeerCertificateQuery::Datetime(dt) => sqlx::query!(r#"select data as "data: &'static [u8]" from certificates where creation_timestamp>=?"#, dt)
                    .map(|v| v.data)
                    .fetch(&ctx.db),
            }
                .map(|v| match v {
                    Ok(v) => Ok(v),
                    Err(e) => Err(Self::QueryError::from(e)),
                })
        )
    }

    /// Generate and execute an SQL query that will return the resource IDs of records that match the given
    /// [Query](Self::Query)
    async fn query_ids(ctx: &Context, query: Self::Query) -> Pin<Box<dyn Stream<Item = Result<PeerCertificateId, Self::QueryError>>>> {
        Box::pin(
            match query {
                PeerCertificateQuery::Fingerprint(userid) => sqlx::query!(r#"select userid as "userid: PeerCertificateId" from certificates where userid=?"#, userid)
                    .map(|v| v.userid)
                    .fetch(&ctx.db),
                PeerCertificateQuery::Datetime(dt) => sqlx::query!(r#"select userid as "userid: PeerCertificateId" from certificates where creation_timestamp>=?"#, dt)
                    .map(|v| v.userid)
                    .fetch(&ctx.db),
            }
            .map(|v| v.map_err(Into::into))
        )
    }
    
    /// Fetch the bytes that can be decoded to an instance of this resource type
    async fn fetch_bytes<'c>(ctx: &'c Context, id: PeerCertificateId) -> Result<&'c [u8], Self::QueryError> {
        sqlx::query!(r#"select data as "data: &'static [u8]" from certificates where userid=?"#, id)
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
