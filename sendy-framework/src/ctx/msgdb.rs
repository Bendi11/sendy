use std::{path::PathBuf, ops::Range};

use base64::{engine::GeneralPurposeConfig, Engine};
use bytes::Bytes;
use chrono::{DateTime, Utc};

use crate::{FromBytes, model::{message::ChatMessageId, crypto::SHA256_HASH_LEN_BYTES}, FromBytesError, ToBytes};


/// A container for all messages that are being stored locally, ready to be sent to peers that
/// request them / frontend
#[derive(serde::Serialize, serde::Deserialize)]
pub struct MessageDatabase {
    /// For now, database is a naive directory full of timestamped files
    dir: PathBuf,
}

impl MessageDatabase {
    const ENCODER: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        GeneralPurposeConfig::new().with_encode_padding(false)
    );

    /// Create a new [MessageDatabase] that stores messages in the given filesystem directory
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn store(&self, ts: &DateTime<Utc>, id: &ChatMessageId, msg: &[u8]) -> Result<(), MessageStoreError> {
        let filename = format!(
            "{}.{}",
            Self::ENCODER.encode(ts.write_to_vec()),
            Self::ENCODER.encode(id.write_to_vec())
        );
        std::fs::write(
            self.dir.join(filename),
            msg
        )?;

        Ok(())
    }
    
    /// Load a message by the given ID and return the encrypted and signed bytes that represent the
    /// message
    pub fn load(&self, msg_id: &ChatMessageId) -> Option<Vec<u8>> {
        let iter = match std::fs::read_dir(&self.dir) {
            Ok(iter) => iter,
            Err(e) => {
                log::error!("Failed to read chat messages directory: {}", e);
                return None
            }
        };

        for entry in iter {
            if let Ok(entry) = entry {
                if let Some(id_base64) = entry.file_name().to_string_lossy().split('.').nth(1) {
                    if let Ok(id) = Self::ENCODER.decode(id_base64) {
                        if let Ok(id) = <[u8 ; SHA256_HASH_LEN_BYTES]>::try_from(id) {
                            let id = ChatMessageId(id);
                            if id == *msg_id {
                                return std::fs::read(
                                    entry.path()
                                ).ok()
                            }
                        }
                    }
                }
            }
        }

        None
    }
    
    /// Lookup all chat messages sent by any peer in the given timespan
    pub fn get_in_range(&self, span: Range<DateTime<Utc>>) -> impl Iterator<Item = ChatMessageId> {
        std::iter::empty()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MessageStoreError {
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Invalid message bytes: {0}")]
    InvalidMessage(#[from] FromBytesError),
}

#[derive(Debug, thiserror::Error)]
pub enum MessageLoadError {
    #[error("I/O error {0}")]
    IO(#[from] std::io::Error),
    #[error("No file with the given id found")]
    NotFound,
}
