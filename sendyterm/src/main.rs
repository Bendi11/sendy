use std::net::{SocketAddrV4, Ipv4Addr};

use sendy_framework::net::sock::ReliableSocket;


#[tokio::main(flavor = "current_thread")]
async fn main() {
    ReliableSocket::tunnel_connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1241)).await.unwrap();
}
