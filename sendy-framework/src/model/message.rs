use bytes::BufMut;
use chrono::{DateTime, Utc};

use crate::{ToBytes, FromBytes};

use super::crypto::{UserId, SHA256_HASH_LEN_BYTES};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ChatMessageId(pub(crate) [u8 ; SHA256_HASH_LEN_BYTES]);

/// The full data contained in a chat message, without a signature or encryption applied
#[derive(Debug)]
pub struct ChatMessage {
    /// ID of the author of the message
    pub author: UserId,
    /// ID of the message, separate from the timestamp
    pub id: ChatMessageId,
    /// Timestamp that the message was sent at
    pub timestamp: DateTime<Utc>,
    /// Content of the message in UTF-8
    pub body: String,
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
impl ToBytes for ChatMessage {
    fn write<W: BufMut>(&self, mut buf: W) {
        self.author.write(&mut buf);
        self.id.write(&mut buf);
        self.timestamp.write(&mut buf);
        self.body.write(&mut buf);
    }

    fn size_hint(&self) -> Option<usize> {
        self.author.size_hint()
            .zip(self.id.size_hint())
            .zip(self.timestamp.size_hint())
            .zip(self.body.size_hint())
            .map(|(((s1, s2), s3), s4)| s1 + s2 + s3 + s4)
    }
}

impl FromBytes for ChatMessage {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, crate::FromBytesError> {
        Ok(Self {
            author: UserId::parse(reader)?,
            id: ChatMessageId::parse(reader)?,
            timestamp: DateTime::<Utc>::parse(reader)?,
            body: String::parse(reader)?,
        })
    }
}
