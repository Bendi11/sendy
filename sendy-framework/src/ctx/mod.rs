use std::net::Ipv4Addr;
use std::{sync::Arc, net::SocketAddr};
use dashmap::DashMap;
use sendy_wireformat::FromBytesError;
use signature::Signer;

use chrono::{Utc, Duration};
use sqlx::SqlitePool;

use crate::model::cert::{PeerCertificate, UnsignedPeerCertificate, PeerCapabilities};
use crate::msg::conn::ConnResponseErr;
use crate::{SocketConfig, ToBytes, FromBytes};
use crate::model::crypto::PrivateKeychain;
use crate::sock::{ReliableSocket, PacketKind, ReliableSocketTransmitter};

mod handle;
pub mod res;

pub use res::Resource;

use self::res::cert::{PeerCertificateHandleError, PeerCertificateId};

/// The main interface for interacting with the Sendy network - contains state for all peer
/// connections and resource persistence
#[derive(Debug)]
pub struct Context {
    /// Manager for all lower-level UDP operations
    socks: ReliableSocket,
    /// Connected and authenticated peers
    pub(crate) peers: DashMap<SocketAddr, Peer>,
    /// Keychain used to sign and encrypt messages
    pub(crate) keychain: PrivateKeychain,
    /// Signed certificate for our keys
    pub(crate) certificate: PeerCertificate,
    /// Connection to an sqlite database used to store all resources
    pub(crate) db: SqlitePool,
}

/// An authenticated connection to a remote peer
#[derive(Debug)]
pub(crate) struct Peer {
    /// ID of the certificate for this peer
    pub cert: PeerCertificateId,
    /// Flow control state used to transmit packets to the peer
    pub tx: ReliableSocketTransmitter,
}


impl Context {
    /// Create a new `Context` with the given keychain for authentication and encryption,
    /// configuration options, and database connection pool for resource storage
    pub async fn new(
        keychain: PrivateKeychain,
        cfg: SocketConfig,
        username: String,
    ) -> Result<Arc<Self>, sqlx::Error> {
        let socks = ReliableSocket::new(cfg);
        
        let db = sqlx::SqlitePool::connect("sqlite://./sendy.db?mode=rwc").await?;
        sqlx::migrate!("../migrations").run(&db).await?;

        let certificate = UnsignedPeerCertificate {
            keychain: keychain.public(),
            sockaddr: std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            username,
            capabilities: PeerCapabilities::all(),
            timestamp: Utc::now(),
            ttl: Duration::seconds(900),
        };

        let certificate = {
            let bytes = match certificate.encode_to_vec() {
                Ok(v) => v,
                Err(e) => {
                    panic!("Failed to encode host certificate: {}", e);
                }
            };
            let signature = keychain.authentication.sign(&bytes);
            PeerCertificate {
                cert: certificate,
                signature,
            }
        };

        let this = Arc::new(Self {
            socks,
            peers: DashMap::new(),
            keychain,
            certificate: certificate.clone(),
            db,
        });


        let id = PeerCertificate::store(&this, certificate).await.unwrap();
        log::trace!("ID is {}", id.short());

        log::trace!("signature is {:x}", PeerCertificate::fetch(&this, id).await.unwrap().signature);

        Ok(this)
    }

    /// Listen for incoming connections on the given port
    #[inline]
    pub async fn listen(&self, port: u16) -> std::io::Result<()> {
        self.socks.new_binding(port).await
    }
    
    /// Connect to the peer at the given IP address and port
    pub async fn connect(&self, addr: SocketAddr) -> Result<(), SendyError> {
        if self.peers.contains_key(&addr) {
            return Ok(())
        }

        let tx = self.socks.create_transmitter(addr).await?;

        log::trace!("Transmitted certificate");

        let resp = self
            .socks
            .send_wait_response(&tx, PacketKind::Conn, &self.certificate)
            .await?;

        let cert = match resp.await {
            Ok(response) => PeerCertificate::handle(self, response).await?,
            Err(reason) => {
                let err =  ConnResponseErr::full_decode_from_slice(&reason)?;
                log::error!("Failed to connect to remote {addr}: {err}");
                return Err(SendyError::ResponseError)
            }
        };

        let peer = Peer {
            tx,
            cert: cert.clone(),
        };

        self.peers.insert(addr, peer);

        Ok(())
    }
}

/// Errors that may occur when executing operations over the sendy network
#[derive(Debug, thiserror::Error)]
pub enum SendyError {
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),
    #[error("A remote peer responded with an error message")]
    ResponseError,
    #[error("Failed to handle certificate resource: {0}")]
    Certificate(#[from] PeerCertificateHandleError),
    #[error("Failed to decode a value from received bytes: {0}")]
    FromBytes(#[from] FromBytesError),
}
