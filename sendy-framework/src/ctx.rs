use std::net::{IpAddr, SocketAddr};

use crate::{net::{sock::ReliableSocket, msg::MessageKind}, model::crypto::{PrivateKeychain, SignedCertificate}, peer::{PeerConnection, Peer}, req::{ConnectAuthenticateRequest, ConnectAuthenticateResponse}, ser::{FromBytes, FromBytesError}};

/// Shared state used to execute all peer to peer operations
#[derive(Debug)]
pub struct Context {
    /// Manager for all peer connections
    pub(crate) socks: ReliableSocket,
    /// Self-signed certificate stating that the public IP of this node owns the public
    /// authentication and encryption keys it claims
    certificate: SignedCertificate,
    /// Collection of the host's crypto keys
    keychain: PrivateKeychain,
}

impl Context {
    /// Create a new global context from keychain and public IP
    pub async fn new(keychain: PrivateKeychain, publicip: IpAddr) -> Self {
        let certificate = keychain.certificate(publicip);
        let socks = ReliableSocket::new(Default::default()).await;

        Self {
            socks,
            certificate,
            keychain,
        }
    }
    
    /// Create a connection to the given IP address on the port specified by `peer`, exchanging
    /// authentication and encryption data with the peer
    pub async fn connect(&self, peer: SocketAddr) -> Result<Peer, PeerConnectError> {
        let conn = self.socks.connect(peer).await?;

        let peer = PeerConnection::new(conn);

        let resp = peer
                .send_wait_response(self, &ConnectAuthenticateRequest)
                .await?;


        let send_own = async {
            loop {
                let msg = peer.recv().await;
                if msg.kind == MessageKind::AuthConnect {
                    peer.respond(self, &msg, ConnectAuthenticateResponse {
                        cert: self.certificate.clone(),
                    }).await?;
                    break Result::<_, PeerConnectError>::Ok(())
                }
            }
        };


        let resp = async {
            let resp = resp.await;
            let response = ConnectAuthenticateResponse::read_from_slice(&resp)?;

            if !response.cert.verify(&response.cert.cert().keychain().auth) ||
                response.cert.cert().owner() != &peer.remote().ip() {
                return Err(PeerConnectError::InvalidCertificateSignature)
            }

            Ok(response.cert)
        };
    
        let (cert, result) = tokio::join!(resp, send_own);
        result?;
        let cert = cert?;

        Ok(Peer {
            conn: peer,
            cert,
        })
    }
}


#[derive(Debug, thiserror::Error)]
pub enum PeerConnectError {
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Peer's certificate signature is invalid")]
    InvalidCertificateSignature,
    #[error("Peer's response could not be parsed")]
    Parse(#[from] FromBytesError),
}
