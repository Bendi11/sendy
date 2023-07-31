use std::{net::{IpAddr, SocketAddr}, sync::Arc};

use crate::{net::{sock::ReliableSocket, msg::MessageKind}, model::crypto::{PrivateKeychain, SignedCertificate}, peer::Peer, req::{ConnectAuthenticateRequest, ConnectAuthenticateResponse}, ser::FromBytes};

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

        let peer = Arc::new(Peer::new(conn));
        let resp = peer.send_wait_response(self, ConnectAuthenticateRequest).await.unwrap().await.unwrap();
        

        let p2 = peer.clone();
        let resp = async {
            let resp = ConnectAuthenticateResponse::parse(
                &mut untrusted::Reader::new(untrusted::Input::from(&resp))
            ).unwrap();

            if !resp.cert.verify(&resp.cert.cert().keychain().auth) {
                log::error!("Invalid cert");
            } else {
                log::error!("Got certificate {:?}", resp.cert);
            }
        };
        
        let send_own = async {
            loop {
                let msg = peer.recv().await;
                if msg.kind == MessageKind::AuthConnect {
                    log::trace!("RESPONDING");
                    peer.respond(self, &msg, ConnectAuthenticateResponse {
                        cert: self.certificate.clone(),
                    }).await.unwrap();
                }
            }
        };

        tokio::join!(resp, send_own);

        Ok(Arc::into_inner(peer).unwrap())
    }
}
