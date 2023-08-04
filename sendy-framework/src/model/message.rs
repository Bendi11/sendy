use bytes::BufMut;
use chrono::{DateTime, Utc};

use crate::{ToBytes, FromBytes};

use super::crypto::{UserId, SHA256_HASH_LEN_BYTES};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ChatMessageId(pub(crate) [u8 ; SHA256_HASH_LEN_BYTES]);

/// Data of a message that is allowed to be unencrypted when sent to other peers
#[derive(Debug)]
pub struct ChatMessageMetadata {
    /// ID of the author of the message
    pub author: UserId,
    /// ID of the message, separate from the timestamp
    pub id: ChatMessageId,
    /// Timestamp that the message was sent at
    pub timestamp: DateTime<Utc>,
}

impl ToBytes for ChatMessageId {
    fn write<B: BufMut>(&self, buf: B) {
        self.0.write(buf)
    }

    fn size_hint(&self) -> Option<usize> {
        self.0.size_hint()
    }
}
impl FromBytes for ChatMessageId {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, crate::FromBytesError> {
        <[u8;SHA256_HASH_LEN_BYTES]>::parse(reader).map(Self)
    }
}

/// Format:
///
/// author - [UserId]
/// id - [ChatMessageId]
/// timestamp - [DateTime<Utc>]
/// body - [String]
impl ToBytes for ChatMessageMetadata {
    fn write<W: BufMut>(&self, mut buf: W) {
        self.author.write(&mut buf);
        self.id.write(&mut buf);
        self.timestamp.write(&mut buf);
    }

    fn size_hint(&self) -> Option<usize> {
        self.author.size_hint()
            .zip(self.id.size_hint())
            .zip(self.timestamp.size_hint())
            .map(|((s1, s2), s3)| s1 + s2 + s3)
    }
}

impl FromBytes for ChatMessageMetadata {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, crate::FromBytesError> {
        Ok(Self {
            author: UserId::parse(reader)?,
            id: ChatMessageId::parse(reader)?,
            timestamp: DateTime::<Utc>::parse(reader)?,
        })
    }
}
