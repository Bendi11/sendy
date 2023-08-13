use std::net::{IpAddr, SocketAddr};

use dashmap::DashMap;

use crate::{
    model::{
        channel::{ChannelId, KeyedChannel},
        crypto::{PrivateKeychain, SignedCertificate},
    },
    net::{
        msg::{MessageKind, ReceivedMessage},
        sock::{PacketKind, ReliableSocket},
    },
    peer::Peer,
    req::{
        ChannelInviteRequest, ChannelInviteResponse, ConnectAuthenticate, Request,
    },
    ser::{FromBytes, FromBytesError},
    ToBytes,
};

use self::msgdb::MessageDatabase;

mod msgdb;

/// Shared state used to execute all peer to peer operations
#[derive(Debug)]
pub struct Context {
    /// Manager for all peer connections
    pub(crate) socks: ReliableSocket,
    /// A collection of all peers that have been successfully authenticated
    pub(crate) authenticated_peers: DashMap<IpAddr, Peer>,
    /// All persistent state for the context
    pub(crate) state: ContextState,
    /// Self-signed certificate stating that the public IP of this node owns the public
    /// authentication and encryption keys it claims
    certificate: SignedCertificate,
    /// Collection of the host's crypto keys
    pub(crate) keychain: PrivateKeychain,
}

/// State that must be persisted across sessions
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct ContextState {
    /// Message channels that we have been invited to and generated the keys for
    pub channels: DashMap<ChannelId, KeyedChannel>,
    /// A collection of all currently-stored messages
    pub messages: MessageDatabase,
}

/// Events that may be sent to the frontend via a channel
#[derive(Debug)]
pub enum SendyEvent {
    /// A peer with the given information is attempting to make a connection
    AttemptedPeerConnection,
}

impl Context {
    /// Create a new global context from keychain and public IP
    pub async fn new(keychain: PrivateKeychain, publicip: IpAddr, username: String) -> Self {
        let certificate = keychain.certificate(publicip, username);
        let socks = ReliableSocket::new(Default::default()).await;

        Self {
            socks,
            authenticated_peers: DashMap::new(),
            state: ContextState::default(),
            certificate,
            keychain,
        }
    }

    /// Bind to the given port and listen for new messages
    pub async fn listen(&self, port: u16) -> std::io::Result<()> {
        self.socks.new_binding(port).await
    }

    /// Create a connection to the given IP address on the port specified by `peer`, exchanging
    /// authentication and encryption data with the peer
    pub async fn connect(&self, peer: SocketAddr) -> Result<(), PeerConnectError> {
        let conn = self.socks.connect(peer).await?;

        let resp = self
            .socks
            .send_wait_response(
                &conn,
                ConnectAuthenticate::KIND,
                ConnectAuthenticate {
                    cert: self.certificate.clone(),
                },
            )
            .await?;

        let resp = resp.await;
        let response = ConnectAuthenticate::read_from_slice(&resp)?;

        if !Self::validate_cert(&response.cert, &peer.ip()) {
            self.socks
                .send_wait_response(&conn, MessageKind::Terminate, ())
                .await?
                .await;

            return Err(PeerConnectError::InvalidCertificateSignature);
        }

        self.authenticated_peers.insert(
            peer.ip(),
            Peer {
                conn,
                cert: response.cert,
            },
        );

        Ok(())
    }

    fn validate_cert(cert: &SignedCertificate, peer: &IpAddr) -> bool {
        cert.verify(&cert.cert().keychain().auth) && cert.cert().owner() == peer
    }

    /// Handle a single request from a remote
    async fn handle_request(&self, req: &ReceivedMessage) -> Result<(), HandleRequestError> {
        match req.kind {
            MessageKind::AuthConnect => {
                let msg = ConnectAuthenticate::read_from_slice(&req.bytes)?;

                match self.authenticated_peers.get(&req.from.ip()) {
                    Some(_) => {
                        log::trace!("TODO: Authenticated peer send auth connect message")
                    }
                    None => {
                        let conn = self.socks.connect(req.from).await?;

                        self.socks
                            .send_with_id(
                                &conn,
                                req.id,
                                PacketKind::Message(MessageKind::Respond),
                                self.certificate.write_to_vec(),
                            )
                            .await?;

                        self.authenticated_peers.insert(
                            req.from.ip(),
                            Peer {
                                conn,
                                cert: msg.cert,
                            },
                        );
                    }
                }
            }
            MessageKind::Test => (),
            MessageKind::InviteToChannel => {
                let peer = self
                    .authenticated_peers
                    .get(&req.from.ip())
                    .ok_or(HandleRequestError::NoPeer)?;
                let ChannelInviteRequest { channel } =
                    ChannelInviteRequest::read_from_slice(&req.bytes)?;
                let chid = channel.id;
                let keyed = channel
                    .gen_key()
                    .map_err(|e| HandleRequestError::KDF { chid, e })?;

                self.state.channels.insert(chid, keyed);

                peer.respond(&self, req, &ChannelInviteResponse::ChannelJoined)
                    .await?;
            },
            MessageKind::PublishPost => {
                
            },
            MessageKind::Terminate => {
                log::trace!("Connection terminated with {}", req.from);
            }
            MessageKind::Respond => {
                log::error!("Unhandled respond message");
            }
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

#[derive(Debug, thiserror::Error)]
enum HandleRequestError {
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Failed to deserialize message: {0}")]
    FromBytes(#[from] FromBytesError),
    #[error("Failed to generate a symmetric key for channel {chid}: {e}")]
    KDF { chid: ChannelId, e: argon2::Error },
    #[error("Got a message from a peer that has not yet been authenticated")]
    NoPeer,
}

impl Default for ContextState {
    fn default() -> Self {
        Self {
            channels: DashMap::new(),
            messages: MessageDatabase::new("./sendydb".into()),
        }
    }
}
