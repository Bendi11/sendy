use crate::{Context, sock::FinishedMessage, msg::{Conn, Message}, model::cert::PeerCertificate, FromBytesError, ctx::res::{Resource, cert::PeerCertificateHandleError}};

impl Context {
    /// Handle a received message from another peer
    async fn handle_message(&self, msg: FinishedMessage) -> Result<(), HandleMessageError> {
        match msg.kind {
            Conn::TAG => {
                let certificate = PeerCertificate::handle(self, msg.payload).await?;
            },
            other => log::error!("Unrecognized message tag {:X}", other as u8),
        }

        Ok(())
    }
}

/// Any error that occurs when handling a received message
#[derive(Debug, thiserror::Error)]
enum HandleMessageError {
    #[error("Failed to decode a value from message buffer: {0}")]
    Parse(#[from] FromBytesError),
    #[error("Failed to decode certificate {0}")]
    CertificateHandle(#[from] PeerCertificateHandleError),
}
