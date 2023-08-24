use crate::{Context, sock::FinishedMessage, msg::{Conn, Message}};


impl Context {
    async fn handle_message(&self, msg: FinishedMessage) {
        match msg.kind {
            Conn::TAG => {
                
            },
            other => log::error!("Unrecognized message tag {:X}", other as u8),
        }
    }
}
