use std::net::{IpAddr, SocketAddr};

use dashmap::DashMap;
use parking_lot::Mutex;
use slab::Slab;
use tokio::sync::oneshot;

use crate::{net::{sock::{ReliableSocket}, msg::{MessageKind, ReceivedMessage}}, model::crypto::{PrivateKeychain, SignedCertificate}, peer::Peer, req::{ConnectAuthenticate, Request}, ser::{FromBytes, FromBytesError}};

/// Shared state used to execute all peer to peer operations
#[derive(Debug)]
pub struct Context {
    /// Manager for all peer connections
    pub(crate) socks: ReliableSocket,
    /// A collection of all peers that have been successfully authenticated
    pub(crate) authenticated_peers: DashMap<IpAddr, Peer>,
    /// Self-signed certificate stating that the public IP of this node owns the public
    /// authentication and encryption keys it claims
    certificate: SignedCertificate,
    /// Collection of the host's crypto keys
    pub(crate) keychain: PrivateKeychain,
}

#[derive(Debug)]
enum AuthenticationState {
    Authenticated(SignedCertificate),
    AuthenticationFailed,
}

impl Context {
    /// Create a new global context from keychain and public IP
    pub async fn new(keychain: PrivateKeychain, publicip: IpAddr) -> Self {
        let certificate = keychain.certificate(publicip);
        let socks = ReliableSocket::new(Default::default()).await;

        Self {
            socks,
            authenticated_peers: DashMap::new(),
            certificate,
            keychain,
        }
    }
    
    /// Create a connection to the given IP address on the port specified by `peer`, exchanging
    /// authentication and encryption data with the peer
    pub async fn connect(&self, peer: SocketAddr) -> Result<Peer, PeerConnectError> {
        let conn = self.socks.connect(peer).await?;

        let resp = self
                .socks
                .send_wait_response(&conn, ConnectAuthenticate::KIND, ConnectAuthenticate { cert: self.certificate.clone() })
                .await?;
        
        let resp = resp.await;
        let response = ConnectAuthenticate::read_from_slice(&resp)?;

        if !Self::validate_cert(&response.cert, &peer.ip()) {
            self
                .socks
                .send_wait_response(&conn, MessageKind::Terminate, ())
                .await?;

            return Err(PeerConnectError::InvalidCertificateSignature)
        }

        Ok(Peer {
            conn,
            cert: response.cert,
        })
    }

    fn validate_cert(cert: &SignedCertificate, peer: &IpAddr) -> bool {
        cert.verify(&cert.cert().keychain().auth) &&
            cert.cert().owner() == peer
    }

    async fn handle_request(&self, req: &ReceivedMessage) -> Result<(), FromBytesError> {
        match req.kind {
            MessageKind::AuthConnect => {
                let msg = ConnectAuthenticate::read_from_slice(&req.bytes)?;

            },
            MessageKind::Test => (),
            MessageKind::InviteToChannel => {
                
            },
            MessageKind::Terminate => {
                log::trace!("Connection terminated with {}", req.from);
            },
            MessageKind::Respond => {
                log::error!("Unhandled respond message");
            },
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PeerConnectError {
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Peer's certificate signature is invalid")]
    InvalidCertificateSignature,
    #[error("Peer rejected local certificate")]
    RejectedCertificate,
    #[error("Timeout while waiting for remote authentication")]
    AuthenticationTimeout,
    #[error("Peer's response could not be parsed")]
    Parse(#[from] FromBytesError),
}
