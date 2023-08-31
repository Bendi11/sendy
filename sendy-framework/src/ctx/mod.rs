use bytes::Bytes;
use dashmap::DashMap;
use futures::Future;
use rsa::pkcs1v15::VerifyingKey;
use sendy_wireformat::FromBytesError;
use sha2::Sha256;
use signature::Signer;
use std::net::Ipv4Addr;
use std::{net::SocketAddr, sync::Arc};

use chrono::{Duration, Utc};
use sqlx::migrate::MigrateError;
use sqlx::SqlitePool;

use crate::model::cert::{PeerCapabilities, PeerCertificate, UnsignedPeerCertificate};
use crate::model::crypto::PrivateKeychain;
use crate::msg::{Transaction, Message};
use crate::msg::conn::ConnResponseErr;
use crate::sock::{PacketKind, ReliableSocket, ReliableSocketTransmitter};
use crate::{FromBytes, SocketConfig, ToBytes};

mod handle;
pub mod res;

pub use res::Resource;

use self::res::ResourceError;
use self::res::cert::PeerCertificateId;

/// The main interface for interacting with the Sendy network - contains state for all peer
/// connections and resource persistence
#[derive(Debug)]
pub struct Context {
    /// Manager for all lower-level UDP operations
    socks: ReliableSocket,
    /// A map of IP + port combinations to connected and authenticated peers
    pub(crate) peers: DashMap<SocketAddr, Arc<Peer>>,
    /// Keychain used to sign and encrypt messages
    pub(crate) keychain: PrivateKeychain,
    /// Signed certificate for our keychain that we transmit to other peers to establish an
    /// authenticated connection
    pub(crate) certificate: PeerCertificate,
    /// Connection to a sqlite database used to store all resources
    pub(crate) db: SqlitePool,
    /// A map of known certificate fingerprints to their associated public authentication keys
    pub(crate) quick_certs: DashMap<PeerCertificateId, VerifyingKey<Sha256>>,
}

/// An authenticated connection to a remote peer, storing transmission flow control state for the
/// peer and a certificate ID used to authenticate the user
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
    ///
    /// Performs sqlite database migrations, creates and signs a certificate for the given
    /// [PrivateKeychain], and stores this new certificate in the resource database
    pub async fn new(
        keychain: PrivateKeychain,
        cfg: SocketConfig,
        username: String,
    ) -> Result<Arc<Self>, SendyError> {
        let socks = ReliableSocket::new(cfg);

        let db = sqlx::SqlitePool::connect("sqlite://./sendy.db?mode=rwc").await?;
        sqlx::migrate!("../migrations").run(&db).await?;

        let certificate = UnsignedPeerCertificate {
            keychain: keychain.public(),
            sockaddr: std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            username,
            capabilities: PeerCapabilities::all(),
            timestamp: Utc::now(),
            ttl: Duration::seconds(900000),
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

        PeerCertificate::store(&this, certificate).await?;

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
            return Ok(());
        }

        let tx = self.socks.create_transmitter(addr).await?;

        log::trace!("Transmitted certificate to {addr}");

        let resp = self
            .socks
            .send_wait_response(&tx, PacketKind::Conn, &self.certificate)
            .await?;

        let cert = match resp.await {
            Ok(response) => PeerCertificate::handle(self, response).await?,
            Err(reason) => {
                let err = ConnResponseErr::full_decode_from_slice(&reason)?;
                log::error!("Failed to connect to remote {addr}: {err}");
                return Err(SendyError::ResponseError);
            }
        };

        let peer = Peer {
            tx,
            cert: cert.clone(),
        };

        self.peers.insert(addr, Arc::new(peer));

        Ok(())
    } 
    
    /// Commit a transaction with another peer, submitting a request and awaiting a response
    pub async fn transact<T: Transaction>(&self, to: &Peer, req: &T::Request) -> Result<Result<T::OkResponse, T::ErrResponse>, SendyError> {
        let resp = self.msg(to, req).await?;

        Ok(match resp.await {
            Ok(bytes) => Ok(T::OkResponse::full_decode_from_slice(&bytes)?),
            Err(bytes) => Err(T::ErrResponse::full_decode_from_slice(&bytes)?),
        })
    }
    
    /// Send a message to the given peer, dropping all peer state if e.g. the connection times out
    /// and validating the message with the peer's public key
    ///
    /// All higher-level [Context] procedures should utilize this method over
    /// [send_wait_response](ReliableSocket::send_wait_response) as it handles dropping connections
    pub async fn msg<M: Message>(&self, to: &Peer, msg: &M) -> Result<impl Future<Output = Result<Bytes, Bytes>>, SendyError> {
        //todo implement connection timeout
        let resp = self.socks.send_wait_response(&to.tx, M::TAG, msg).await?;
        Ok(resp)
    }
}

/// Errors that may occur when executing operations over the sendy network
#[derive(Debug, thiserror::Error)]
pub enum SendyError {
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Failed to execute database operation: {0}")]
    Sql(#[from] sqlx::Error),
    #[error("Failed to run database migrations: {0}")]
    Migration(#[from] MigrateError),
    #[error("A remote peer responded with an error message")]
    ResponseError,
    #[error("Failed to handle resource: {0}")]
    Resource(#[from] ResourceError),
    #[error("Failed to decode a value from received bytes: {0}")]
    FromBytes(#[from] FromBytesError),
}
