use chrono::{Utc, Duration, NaiveDateTime};

use crate::{ToBytes, FromBytesError, FromBytes};

use super::{ByteWriter, ToBytesError};

/// Format:
/// UNIX timestamp - 8 bytes
impl ToBytes for chrono::DateTime<Utc> {
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        self.timestamp().encode(buf)
    }

    fn size_hint(&self) -> usize {
        self.timestamp().size_hint()
    }
}

impl FromBytes<'_> for chrono::DateTime<Utc> {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let ts = i64::decode(reader)?;
        let naive = match NaiveDateTime::from_timestamp_millis(ts) {
            Some(dt) => dt,
            None => {
                return Err(FromBytesError::Parsing(format!(
                    "Failed to read UTC timestamp: out of range"
                )))
            }
        };
        Ok(Self::from_utc(naive, Utc))
    }
}

/// Format:
/// Seconds count - 8 bytes
impl ToBytes for Duration {
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        self.num_seconds().encode(buf)
    }
    
    fn size_hint(&self) -> usize {
        self.num_seconds().size_hint()
    }
}
impl FromBytes<'_> for Duration {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        i64::decode(reader)
            .map(Self::seconds)
    }
}
