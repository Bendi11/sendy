use bytes::BufMut;
use chrono::{DateTime, Utc};
use rsa::pkcs1v15::Signature;

use crate::{FromBytes, ToBytes, FromBytesError};

use super::crypto::{UserId, SHA256_HASH_LEN_BYTES};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ChatMessageId(pub(crate) [u8; SHA256_HASH_LEN_BYTES]);

/// Data of a message that is allowed to be unencrypted when sent to other peers
#[derive(Debug)]
pub struct PostMetadata {
    /// ID of the author of the message
    pub author: UserId,
    /// ID of the message, separate from the timestamp
    pub id: ChatMessageId,
    /// Timestamp that the message was sent at
    pub timestamp: DateTime<Utc>,
}

/// An unsigned post as it is sent to peers, with unencrypted metadata attached
#[derive(Debug)]
pub struct UnsignedPost {
    /// Unencrypted metadata of the post
    pub meta: PostMetadata,
    /// Encrypted bytes of the message body
    pub body: Vec<u8>,
}


impl ToBytes for UnsignedPost {
    fn write<W: bytes::BufMut>(&self, mut buf: W) {
        self.meta.write(&mut buf);
        self.body.write(&mut buf);
    }

    fn size_hint(&self) -> Option<usize> {
        self.meta.size_hint()
            .zip(self.body.size_hint())
            .map(|(s1, s2)| s1 + s2)
    }
}

impl FromBytes for UnsignedPost {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let meta = PostMetadata::parse(reader)?;
        let body = Vec::<u8>::parse(reader)?;
        Ok(Self {
            meta,
            body,
        })
    } 
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
        <[u8; SHA256_HASH_LEN_BYTES]>::parse(reader).map(Self)
    }
}

/// Format:
///
/// author - [UserId]
/// id - [ChatMessageId]
/// timestamp - [DateTime<Utc>]
impl ToBytes for PostMetadata {
    fn write<W: BufMut>(&self, mut buf: W) {
        self.author.write(&mut buf);
        self.id.write(&mut buf);
        self.timestamp.write(&mut buf);
    }

    fn size_hint(&self) -> Option<usize> {
        self.author
            .size_hint()
            .zip(self.id.size_hint())
            .zip(self.timestamp.size_hint())
            .map(|((s1, s2), s3)| s1 + s2 + s3)
    }
}

impl FromBytes for PostMetadata {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, crate::FromBytesError> {
        Ok(Self {
            author: UserId::parse(reader)?,
            id: ChatMessageId::parse(reader)?,
            timestamp: DateTime::<Utc>::parse(reader)?,
        })
    }
}
