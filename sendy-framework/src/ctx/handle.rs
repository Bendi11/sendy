use std::sync::Arc;

use crate::{
    ctx::{
        res::{ResourceManager, ResourceError},
        Peer, SendyError,
    },
    model::cert::PeerCertificate,
    msg::conn::ConnResponseErr,
    sock::{FinishedMessage, PacketKind},
    Context,
};

impl Context {
    /// Handle a received message from another peer
    async fn handle_message(&self, msg: FinishedMessage) -> Result<(), SendyError> {
        match msg.kind {
            PacketKind::Conn => {
                let cert = match PeerCertificate::handle(self, msg.payload).await {
                    Ok(cert) => cert,
                    Err(e) => {
                        log::error!(
                            "Error when receiving peer certificate from CONN message: {}",
                            e
                        );

                        let resp = match e {
                            ResourceError::InvalidSignature(_) => {
                                ConnResponseErr::InvalidCertificateSignature
                            }
                            ResourceError::Expired => {
                                ConnResponseErr::ExpiredCertificate
                            }
                            _ => ConnResponseErr::Unknown,
                        };

                        let tmp_tx = self.socks.create_transmitter(msg.from).await?;

                        self.socks
                            .send_with_id(&tmp_tx, msg.id, PacketKind::RespondErr, &resp)
                            .await?;

                        return Err(SendyError::Resource(e));
                    }
                };

                log::trace!("Got valid certificate {} from {}", cert.short(), msg.from);

                let tx = self.socks.create_transmitter(msg.from).await?;

                let peer = Peer { cert, tx };

                self.socks
                    .send_with_id(&peer.tx, msg.id, PacketKind::RespondOk, &self.certificate)
                    .await?;

                self.peers.insert(msg.from, Arc::new(peer));

                log::trace!("Connected to {}", msg.from);
            }
            PacketKind::Advertise => {}
            other => log::error!("Unrecognized message tag {:X}", other as u8),
        }

        Ok(())
    }
}
