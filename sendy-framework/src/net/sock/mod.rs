mod packet;
mod recv;
mod tx;

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{atomic::AtomicU8, Arc},
};

use dashmap::DashMap;
pub(crate) use packet::PacketKind;
use tokio::{
    net::UdpSocket,
    sync::Notify,
};

use self::{
    packet::PacketId,
    recv::ReliableSocketRecv,
    tx::ReliableSocketCongestionControl,
};

/// Configuration options for a socket connection
#[derive(Debug)]
pub struct SocketConfig {
    /// Maximum bytes of memory to use when buffering received packets
    pub max_recv_mem: usize,
    /// Transmission window size in packets to start at
    pub transmission_window_sz: u8,
    /// Extra time beyond the estimated round trip time to wait for an ACK packet
    pub extra_wait_for_ack_ms: usize,
}

/// State maintained for each connection to a remote peer, created by a [ReliableSocket]
#[derive(Debug)]
pub(crate) struct ReliableSocketTransmitter {
    /// Address and port of the remote peer
    remote: SocketAddr,
    /// Counter used to create IDs for transmitted messages
    msgid: AtomicU8,
    /// Congestion control to limit the number of messages that may be sent
    congestion: ReliableSocketCongestionControl,
}

/// Wrapper over a UDP socket that is capable of UDP hole punching to connect to another peer, with
/// a minimal reliability layer that guarantees messages are received in the order they are
/// transmitted (unless they dropped for another reason - e.g. the message was too large to accomodate)
#[derive(Debug)]
pub(crate) struct ReliableSocket {
    /// Map of ports to sockets that have been bound to them
    socks: DashMap<u16, UdpSocket>,
    /// Runtime-configurable options for performance and rate limiting
    cfg: SocketConfig,
    /// Map of currently sent packets to their ack wakers
    awaiting_ack: DashMap<PacketId, Arc<Notify>>,
    /// Receiving arm of this socket
    recv: ReliableSocketRecv,
}

impl ReliableSocketTransmitter {
    /// Get the address that this socket is connected to
    #[inline]
    pub const fn remote(&self) -> &SocketAddr {
        &self.remote
    }
}

impl ReliableSocket {
    /// Create a new socket that is not connected to any remote peer
    pub fn new(cfg: SocketConfig) -> Self {
        let recv = ReliableSocketRecv::new(&cfg);

        Self {
            socks: DashMap::new(),
            cfg,
            awaiting_ack: DashMap::new(),
            recv,
        }
    }

    /// Add a listener for packets on the given port
    pub async fn new_binding(&self, port: u16) -> Result<(), std::io::Error> {
        if !self.socks.contains_key(&port) {
            self.socks.insert(
                port,
                UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).await?,
            );
        }

        Ok(())
    }

    /// Create flow control state for a single remote peer, adding a listener for the port that the
    /// peer is located on. Performs no actual network operations.
    pub async fn create_transmitter(&self, addr: SocketAddr) -> std::io::Result<ReliableSocketTransmitter> {
        self.new_binding(addr.port()).await?;

        Ok(ReliableSocketTransmitter {
            msgid: AtomicU8::new(1),
            remote: addr,
            congestion: ReliableSocketCongestionControl::new(&self.cfg),
        })
    }
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            max_recv_mem: 50_000_000,
            transmission_window_sz: 4,
            extra_wait_for_ack_ms: 250,
        }
    }
}
