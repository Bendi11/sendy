use chrono::Utc;
use rsa::pkcs1v15::Signature;
use signature::Verifier;

use crate::{Context, sock::FinishedMessage, msg::{Conn, Message}, model::cert::{UnsignedPeerCertificate, PeerCertificate}, FromBytes, FromBytesError};

impl Context {
    /// Handle a received message from another peer
    async fn handle_message(&self, msg: FinishedMessage) -> Result<(), HandleMessageError> {
        match msg.kind {
            Conn::TAG => {
                let cert = self.parse_validate_peer_certificate(&msg.payload)?;

            },
            other => log::error!("Unrecognized message tag {:X}", other as u8),
        }

        Ok(())
    }
    
    /// Decode and validate a peer's self-signed certificate, returning a valid [SignedCertificate] if the
    /// signature was valid for the public key in the certificate and the timestamp + ttl of the
    /// certificate is still living
    fn parse_validate_peer_certificate(&self, buf: &[u8]) -> Result<PeerCertificate, HandleMessageError> {
        let mut reader = untrusted::Reader::new(untrusted::Input::from(buf));
        let (bytes, cert) = UnsignedPeerCertificate::partial_decode(&mut reader)?;
        let signature = Signature::decode(&mut reader)?;
        
        let now = Utc::now();

        match cert.timestamp <= now {
            true => match cert.timestamp + cert.ttl >= now {
                true => match cert.keychain.verification.verify(bytes.as_slice_less_safe(), &signature) {
                    Ok(_) => {
                        Ok(PeerCertificate {
                            cert,
                            signature,
                        })
                    },
                    Err(e) => Err(PeerCertificateError::InvalidSignature(e).into()),
                },
                false => Err(PeerCertificateError::Expired.into()),
            },
            false => Err(PeerCertificateError::InvalidTimestamp(cert.timestamp).into()),
        }
    }
}

/// Any error that occurs when handling a received message
#[derive(Debug, thiserror::Error)]
enum HandleMessageError {
    #[error("Failed to decode a value from message buffer: {0}")]
    Parse(#[from] FromBytesError),
    #[error("{0}")]
    Certificate(#[from] PeerCertificateError),
}

/// Errors that may occur when verifying a peer's signed certificate
#[derive(Debug, thiserror::Error)]
enum PeerCertificateError {
    #[error("Signature of self-signed certificate was invalid: {0}")]
    InvalidSignature(#[from] signature::Error),
    #[error("Invalid certificate timestamp {0} is in the future")]
    InvalidTimestamp(chrono::DateTime<Utc>),
    #[error("Certificate TTL has expired")]
    Expired,
}
