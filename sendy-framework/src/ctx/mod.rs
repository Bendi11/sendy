use std::{net::{IpAddr, SocketAddr}, sync::Arc};

use dashmap::DashMap;
use rsa::{
    pkcs1v15::Signature,
    signature::Verifier,
};
use tokio::sync::mpsc;

use crate::{
    model::{
        channel::{ChannelId, KeyedChannel},
        crypto::{PrivateKeychain, SignedCertificate, UserId}, post::{UnsignedPost, SignedPost},
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

/// Shared state used to process incoming requests
#[derive(Debug)]
pub struct Context {
    pub(crate) ctx: Arc<ContextInternal>,
    events: mpsc::Receiver<SendyEvent>,
    handler: tokio::task::JoinHandle<()>,
}

/// Shared state used to execute all peer to peer operations
#[derive(Debug)]
pub(crate) struct ContextInternal {
    /// Manager for all peer connections
    pub(crate) socks: ReliableSocket,
    /// A collection of all peers that have been successfully authenticated
    pub(crate) authenticated_peers: DashMap<IpAddr, Arc<Peer>>,
    /// A mapping of all authenticated user IDs to their credentials
    pub(crate) known_peers: DashMap<UserId, Arc<Peer>>,
    /// All persistent state for the context
    pub(crate) state: ContextState,
    /// Self-signed certificate stating that the public IP of this node owns the public
    /// authentication and encryption keys it claims
    certificate: SignedCertificate,
    /// Collection of the host's crypto keys
    pub(crate) keychain: PrivateKeychain,
    /// Events to send to the frontend
    pub(crate) events: mpsc::Sender<SendyEvent>,
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
    PeerConnection(Arc<Peer>),
    /// A peer sent a message from an unknown user
    UnknownUserPost(SignedPost),
    /// A peer sent a message from a known user with an invalid signature
    InvalidSignaturePost(SignedPost),
    /// A peer sent a message from a known user with a valid signature
    /// A peer sent a new valid message
    NewPost(SignedPost),
}

impl Context {
    /// Create a new global context from a keychain, public IP address, and username
    pub async fn new(keys: PrivateKeychain, ip: IpAddr, username: String) -> Self {
        let (ctx, events) = ContextInternal::new(keys, ip, username).await;
        
        let ctx = Arc::new(ctx);
        let context = Arc::clone(&ctx);
        
        let handler = tokio::task::spawn(async move {
            loop {
                let (_, msg) = context.socks.recv().await;
                let context = Arc::clone(&context);
                let _ = tokio::task::spawn(async move {
                    if let Err(e) = context.handle_request(msg).await {
                        log::error!("Failed to handle request: {}", e);
                    }
                }).await;
            }
        });

        Self {
            ctx,
            events,
            handler,
        }
    }

    /// Bind to the given port and listen for new messages
    pub async fn listen(&self, port: u16) -> std::io::Result<()> {
        self.ctx.socks.new_binding(port).await
    }

    /// Create a connection to the given IP address on the port specified by `peer`, exchanging
    /// authentication and encryption data with the peer
    pub async fn connect(&self, peer: SocketAddr) -> Result<(), PeerConnectError> {
        let conn = self.ctx.socks.connect(peer).await?;

        let resp = self
            .ctx
            .socks
            .send_wait_response(
                &conn,
                ConnectAuthenticate::KIND,
                ConnectAuthenticate {
                    cert: self.ctx.certificate.clone(),
                },
            )
            .await?;

        let resp = resp.await;
        let response = ConnectAuthenticate::read_from_slice(&resp)?;

        if !ContextInternal::validate_cert(&response.cert, &peer.ip()) {
            self.ctx.socks
                .send_wait_response(&conn, MessageKind::Terminate, ())
                .await?
                .await;

            return Err(PeerConnectError::InvalidCertificateSignature);
        }
        
        let peer = Arc::new(
            Peer {
                conn,
                cert: response.cert,
            }
        );

        self.ctx.authenticated_peers.insert(
            *peer.certificate().cert().owner(),
            peer,
        );

        Ok(())
    }

}

impl ContextInternal {
    /// Create a new global context from keychain and public IP
    pub async fn new(keychain: PrivateKeychain, publicip: IpAddr, username: String) -> (Self, mpsc::Receiver<SendyEvent>) {
        let certificate = keychain.certificate(publicip, username);
        let socks = ReliableSocket::new(Default::default()).await;

        let (events, rx) = mpsc::channel(16);

        let this = Self {
            socks,
            authenticated_peers: DashMap::new(),
            known_peers: DashMap::new(),
            state: ContextState::default(),
            certificate,
            keychain,
            events,
        };

        (this, rx)
    }

    fn validate_cert(cert: &SignedCertificate, peer: &IpAddr) -> bool {
        cert.verify(&cert.cert().keychain().auth) && cert.cert().owner() == peer
    }

    /// Handle a single request from a peer
    async fn handle_request(&self, req: ReceivedMessage) -> Result<(), HandleRequestError> {
        match req.kind {
            MessageKind::AuthConnect => {
                let msg = ConnectAuthenticate::read_from_slice(&req.bytes)?;

                if !Self::validate_cert(&msg.cert, &req.from.ip()) {
                    return Err(HandleRequestError::InvalidCertificate)
                }

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

                        let peer = Arc::new(
                            Peer {
                                conn,
                                cert: msg.cert,
                            }
                        );


                        self.authenticated_peers.insert(
                            *peer.certificate().cert().owner(),
                            Arc::clone(&peer),
                        );

                        let _ = self.events.send(SendyEvent::PeerConnection(peer)).await;
                    }
                }
            },
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

                peer.respond(&self, &req, &ChannelInviteResponse::ChannelJoined)
                    .await?;
            },
            MessageKind::PublishPost => {
                let mut reader = untrusted::Reader::new(untrusted::Input::from(&req.bytes));
                let (bytes, post) = reader.read_partial(UnsignedPost::parse)?;
                let bytes = bytes.as_slice_less_safe();
                let sig = Signature::parse(&mut reader)?;

                let post = SignedPost {
                    post,
                    sig,
                };

                let event = match self.known_peers.get(&post.post.meta.author) {
                    Some(peer) => {
                        match peer.remote_keys().auth.verify(bytes, &post.sig).is_ok() {
                            true => SendyEvent::NewPost(post),
                            false => SendyEvent::InvalidSignaturePost(post),
                        }
                    },
                    None => SendyEvent::UnknownUserPost(post),
                };

                if let Err(e) = self.events.send(event).await {
                    log::error!("Failed to send event to frontend: {}", e);
                }
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
    #[error("Peer attempted to authenticate with a certificate that has an invalid signature")]
    InvalidCertificate,
}

impl Default for ContextState {
    fn default() -> Self {
        Self {
            channels: DashMap::new(),
            messages: MessageDatabase::new("./sendydb".into()),
        }
    }
}
