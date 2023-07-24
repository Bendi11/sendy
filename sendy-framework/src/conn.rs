use std::{net::Ipv4Addr, time::Duration};

use crypto_box::ChaChaBox;
use tokio::net::UdpSocket;

use crate::ctx::Context;


/// Authenticated session with another client
pub struct Session {
    // Zeroizes shared secret with Drop impl
    secret: ChaChaBox,
}

impl Session {
    
}
