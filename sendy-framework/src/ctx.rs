use std::{net::{IpAddr, SocketAddr}, sync::Arc, time::Duration};

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

        let resp = peer
                .send_wait_response(self, ConnectAuthenticateRequest)
                .await
                .unwrap();


        let send_own = async {
            loop {
                let msg = peer.recv().await;
                log::trace!("recv");
                if msg.kind == MessageKind::AuthConnect {
                    log::trace!("RESPONDING");
                    peer.respond(self, &msg, ConnectAuthenticateResponse {
                        cert: self.certificate.clone(),
                    }).await.unwrap();
                }
            }
        };


        let resp = async {
            let resp = resp.await.unwrap();
            let response = ConnectAuthenticateResponse::parse(
                &mut untrusted::Reader::new(untrusted::Input::from(&resp))
            );
            
            let resp = match response {
                Ok(v) => v,
                Err(e) => {
                    log::error!("FUCK: {}", e);
                    log::error!("message:");
                    for byte in resp {
                        print!("{:0X} ", byte);
                    }

                    println!("\n\nFUCK");
                    
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    panic!()
                }
            };

            if !resp.cert.verify(&resp.cert.cert().keychain().auth) {
                log::error!("Invalid cert");
            } else {
                log::error!("Got certificate {:?}", resp.cert);
            }
        };
    
        tokio::join!(resp, send_own);

        Ok(Arc::into_inner(peer).unwrap())
    }
}
