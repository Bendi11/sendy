use bytes::Bytes;
use chrono::{DateTime, Utc};
use rsa::{pkcs1v15::Signature, signature::Verifier};
use sendy_wireformat::{ToBytes, FromBytes, FromBytesError};
use sqlx::Executor;

use crate::{model::{channel::Channel, cert::PeerCertificate}, Context};

use super::{ResourceId, ResourceError, cert::PeerCertificateId};

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


pub type ChannelId = ResourceId<Channel>;

impl Context {
    /// Handle the reception of a new instance of this resource, performing all needed validation
    /// and potentially inserting a new value into the [Context]'s database.
    pub(crate) async fn receive_channel(&self, bytes: Bytes) -> Result<ChannelId, ResourceError> {
        let reader = untrusted::Input::from(&bytes);
        let (bytes, channel, signature) = reader
            .read_all(FromBytesError::ExtraBytes, |rdr| {
                let (bytes, channel) = Channel::partial_decode(rdr)?;
                let signature = Signature::decode(rdr)?;

                Ok((bytes, channel, signature))
            })?;

        let record = sqlx::query!("select idx, data from certificates where userid=?", channel.owner)
            .fetch_one(&self.db)
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
            self.db.execute(
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
}
