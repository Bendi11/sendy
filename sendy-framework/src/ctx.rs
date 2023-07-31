use std::net::{IpAddr, SocketAddr};

use crate::{net::sock::ReliableSocket, model::crypto::{PrivateKeychain, SignedCertificate}, peer::Peer, req::{ConnectAuthenticateRequest, ConnectAuthenticateResponse}, ser::FromBytes};

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

    pub async fn connect(&self, peer: SocketAddr) -> std::io::Result<Peer> {
        let conn = self.socks.connect(peer).await?;

        let peer = Peer::new(conn);
        let resp = peer.send_wait_response(self, ConnectAuthenticateRequest).await.unwrap().await.unwrap();

        let resp = ConnectAuthenticateResponse::parse(
            &mut untrusted::Reader::new(untrusted::Input::from(&resp))
        ).unwrap();

        if !resp.cert.verify(&resp.cert.cert().keychain().auth) {
            log::error!("Invalid cert");
        } else {
            log::error!("Got certificate {:?}", resp.cert);
        }

        Ok(peer)
    }
}
