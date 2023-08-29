use crate::{model::cert::PeerCertificate, sock::PacketKind, FromBytes, ToBytes};

use super::Message;

/// Conn message used to establish an authenticated connection with another peer
#[derive(Debug, ToBytes, FromBytes)]
pub struct Conn {
    /// Certificate of the connecting peer
    cert: PeerCertificate,
}

/// A successful response to a received [Conn] message with the certificate of the peer that
/// received the message attached
#[derive(Debug, ToBytes, FromBytes)]
pub struct ConnResponseOk {
    cert: PeerCertificate,
}

/// A response when a peer refused a [Conn] message with reason for connection termination attached
#[derive(Debug, ToBytes, FromBytes, thiserror::Error)]
#[repr(u8)]
pub enum ConnResponseErr {
    #[error("Certificate signature is invalid for the public key given in the certificate")]
    InvalidCertificateSignature = 0,
    #[error("The received certificate has expired")]
    ExpiredCertificate = 1,
    #[error("Unable to process the signature for an unknown reason")]
    Unknown = 255,
}

impl Message for Conn {
    const TAG: PacketKind = PacketKind::Conn;
}
