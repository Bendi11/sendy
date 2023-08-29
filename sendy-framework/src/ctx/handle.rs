use crate::{Context, sock::{FinishedMessage, PacketKind}, msg::conn::ConnResponseErr, model::cert::PeerCertificate, FromBytesError, ctx::{res::{Resource, cert::PeerCertificateHandleError}, Peer, SendyError}};

impl Context {
    /// Handle a received message from another peer
    async fn handle_message(&self, msg: FinishedMessage) -> Result<(), SendyError> {
        match msg.kind {
            PacketKind::Conn => {
                let cert = match PeerCertificate::handle(self, msg.payload).await {
                    Ok(cert) => cert,
                    Err(e) => {
                        log::error!("Error when receiving peer certificate from CONN message: {}", e);

                        let resp = match e {
                            PeerCertificateHandleError::InvalidSignature(_) => ConnResponseErr::InvalidCertificateSignature,
                            PeerCertificateHandleError::Expired => ConnResponseErr::ExpiredCertificate,
                            _ => ConnResponseErr::Unknown,
                        };

                        let tmp_tx = self.socks.create_transmitter(msg.from).await?;

                        self
                            .socks
                            .send_with_id(&tmp_tx, msg.id, PacketKind::RespondErr, &resp).await?;


                        return Err(SendyError::Certificate(e));
                    }
                };

                log::trace!("Got valid certificate {} from {}", cert.short(), msg.from);
                
                let tx = self.socks.create_transmitter(msg.from).await?;

                let peer = Peer {
                    cert,
                    tx,
                };

                self
                    .socks
                    .send_with_id(&peer.tx, msg.id, PacketKind::RespondOk, &self.certificate)
                    .await?;

                self.peers.insert(msg.from, peer);

                log::trace!("Connected to {}", msg.from);
            },
            PacketKind::Advertise => {

            },
            other => log::error!("Unrecognized message tag {:X}", other as u8),
        }

        Ok(())
    }
}

/// Any error that occurs when handling a received message
#[derive(Debug, thiserror::Error)]
enum HandleMessageError {
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Failed to decode a value from message buffer: {0}")]
    Parse(#[from] FromBytesError),
    #[error("Failed to decode certificate {0}")]
    CertificateHandle(#[from] PeerCertificateHandleError),
}
