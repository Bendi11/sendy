//! Module defining traits for how rust types get serialized to bytes when transmitted

use bytes::{BufMut, Buf};

/// Trait to be implemented by all types that can be written to a byte buffer
pub trait ToBytes: Sized {
    /// Write the representation of this payload to a buffer of bytes
    fn write<W: BufMut>(&self, buf: W);

    /// Provide the encoded size in bytes of this value
    fn size_hint(&self) -> Option<usize> {
        None
    }
}

/// Trait implemented by all types that may be parsed from a byte buffer
pub trait FromBytes: Sized {
    /// Read bytes the given buffer (multi-byte words should be little endian) to create an
    /// instance of `Self`
    fn parse<R: Buf>(buf: R) -> Result<Self, std::io::Error>;
}
