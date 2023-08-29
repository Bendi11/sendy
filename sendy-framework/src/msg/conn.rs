use crate::{sock::PacketKind, ToBytes, FromBytes};

use super::Message;


/// Conn message used to establish an authenticated connection with another peer
pub struct Conn {

}

impl Message<'_> for Conn {
    const TAG: PacketKind = PacketKind::Conn;
}

impl ToBytes for Conn {
    fn encode<W: crate::ser::ByteWriter>(&self, _: &mut W) -> Result<(), crate::ser::ToBytesError> {
        Ok(())
    }
}
impl FromBytes<'_> for Conn {
    fn decode(_: &mut untrusted::Reader<'_>) -> Result<Self, crate::FromBytesError> {
        Ok(Conn{})
    }
}
