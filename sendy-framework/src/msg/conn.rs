//! The conn transaction is used to setup an authenticated connection with another peer

use crate::{model::cert::PeerCertificate, sock::PacketKind, FromBytes, ToBytes};

use super::{Message, Transaction};

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

impl Message for ConnResponseOk {
    const TAG: PacketKind = PacketKind::RespondOk;
}

impl Message for ConnResponseErr {
    const TAG: PacketKind = PacketKind::RespondErr;
}


struct ConnTransaction;
impl Transaction for ConnTransaction {
    type Request = Conn;
    type OkResponse = ConnResponseOk;
    type ErrResponse = ConnResponseErr;
}
