use bytes::BufMut;

use crate::{
    model::crypto::SignedCertificate, net::msg::MessageKind, FromBytes, FromBytesError, ToBytes,
};

use super::{Request, Response};

/// Request sent to a remote peer requesting the node send certificates with public keys for
/// authentication and encryption
pub struct ConnectAuthenticate {
    pub cert: SignedCertificate,
}

impl Response for ConnectAuthenticate {}
impl Request for ConnectAuthenticate {
    const KIND: MessageKind = MessageKind::AuthConnect;
}

impl ToBytes for ConnectAuthenticate {
    fn write<W: BufMut>(&self, buf: W) {
        self.cert.write(buf)
    }

    fn size_hint(&self) -> Option<usize> {
        self.cert.size_hint()
    }
}
impl FromBytes for ConnectAuthenticate {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        Ok(Self {
            cert: SignedCertificate::parse(reader)?,
        })
    }
}
