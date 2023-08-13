use rsa::pkcs1v15::Signature;

use crate::{model::post::{PostMetadata, UnsignedPost}, FromBytesError, ToBytes, FromBytes, net::msg::MessageKind};

use super::Request;

/// Request sent to notify other peers of a new message
#[derive(Debug,)]
pub struct PublishPostRequest(pub UnsignedPost);

impl Request for PublishPostRequest {
    const KIND: MessageKind = MessageKind::PublishPost;
}

impl ToBytes for PublishPostRequest {
    fn write<W: bytes::BufMut>(&self, buf: W) {
        self.0.write(buf)
    }

    fn size_hint(&self) -> Option<usize> {
        self.0.size_hint()
    }
}

impl FromBytes for PublishPostRequest {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        UnsignedPost::parse(reader).map(Self)
    }
}
