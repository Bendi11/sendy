use bytes::BufMut;
use chrono::{DateTime, Utc};

use crate::{ToBytes, FromBytes};

use super::crypto::{UserId, SHA256_HASH_LEN_BYTES};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ChatMessageId([u8 ; SHA256_HASH_LEN_BYTES]);

/// The full data contained in a chat message, without a signature or encryption applied
#[derive(Debug)]
pub struct ChatMessage {
    /// ID of the author of the message
    author: UserId,
    /// ID of the message, separate from the timestamp
    id: ChatMessageId,
    /// Timestamp that the message was sent at
    timestamp: DateTime<Utc>,
    /// Content of the message in UTF-8
    body: String,
}

impl ToBytes for ChatMessageId {
    fn write<B: BufMut>(&self, mut buf: B) {
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
    fn write<W: BufMut>(&self, buf: W) {
        
    }
}
