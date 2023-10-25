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

use super::{ResourceId, ResourceError};

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

impl Context {
    /// Read a peer's certificate from the given source, handling updates to existing certificates
    /// or inserting a new one
    pub(crate) async fn receive_cert(&self, bytes: Bytes) -> Result<PeerCertificateId, ResourceError> {
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
                            ).execute(&self.db).await?;
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
    
    /// Manually insert a new certificate from the rust-native type, used to add own certificate
    pub(crate) async fn add_certificate(&self, val: PeerCertificate) -> Result<PeerCertificateId, ResourceError> {
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
            ).execute(&self.db).await?;
        }

        Ok(ResourceId::new(fingerprint))
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
