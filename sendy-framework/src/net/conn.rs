use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use tokio::net::UdpSocket;

use crate::ctx::Context;

/// Network connection with another client
pub struct Session {
    sock: UdpSocket,
}

impl Session {
    pub async fn udp_tunnel(
        ctx: &Context,
        node: SocketAddrV4,
    ) -> Result<Self, SessionConnectError> {
        let sock = UdpSocket::bind(node).await?;
        sock.connect(node).await?;

        Ok(Self { sock })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SessionConnectError {
    #[error("I/O Error: {0}")]
    IO(#[from] std::io::Error),
}
