use crate::{sock::PacketKind, ToBytes, FromBytes, model::cert::PeerCertificate};

use super::Message;


/// Conn message used to establish an authenticated connection with another peer
#[derive(Debug, ToBytes, FromBytes)]
pub struct Conn {
    /// Certificate of the connecting peer
    cert: PeerCertificate,
}

/// A successful response to a received [Conn] message with the certificate of the peer that
/// received the message attached
#[derive(Debug)]
pub struct ConnResponseOk {
    cert: PeerCertificate,
}

/// A response when a peer refused a [Conn] message with reason for connection termination attached
#[derive(Debug)]
#[repr(u8)]
pub enum ConnResponseErr {
    /// The received certificate had an invalid signature for the public key in the certificate
    InvalidCertificateSignature,
    /// The received certificate was expired
    ExpiredCertificate,
}

impl Message for Conn {
    const TAG: PacketKind = PacketKind::Conn;
}
