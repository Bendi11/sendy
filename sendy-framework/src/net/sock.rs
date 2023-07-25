use std::io::Cursor;

use tokio::net::UdpSocket;

use super::packet::{PacketHeader, PacketPayload};


const MAX_IN_TRANSIT_MSG: usize = 5;
const MAX_PACKET_SZ: usize = 500;

/// Minimal reliability layer over a UDP connection
#[derive(Debug)]
struct ReliableSocket {
    sock: UdpSocket,
    recv: WaitingPackets,
    tx: WaitingPackets,
}

#[derive(Debug)]
struct WaitingPackets {
    pub waiting_pkts: [Vec<u8> ; MAX_IN_TRANSIT_MSG],
    pub msg_block_counts: [u32 ; MAX_IN_TRANSIT_MSG],
    pub waiting_pkt_header: [PacketHeader ; MAX_IN_TRANSIT_MSG],
    pub waiting_pkt_ids: [u8 ; MAX_IN_TRANSIT_MSG],
}

impl ReliableSocket {
    pub async fn recv(&self) -> Vec<u8> {
        let mut buf = [0u8 ; MAX_PACKET_SZ];
        loop {
            let pkt = self.sock.recv(&mut buf).await.unwrap();
            let mut buf = Cursor::new(&buf);
            let header = PacketHeader::parse(&mut buf).unwrap();
            

        }
    }
}
