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

type VecToBytesLenType = u32;

impl<T: ToBytes> ToBytes for Vec<T> {
    fn write<B: BufMut>(&self, mut buf: B) {
        buf.put_u32_le(self.len() as VecToBytesLenType);
        for elem in self.iter() {
            elem.write(&mut buf);
        }
    }

    fn size_hint(&self) -> Option<usize> {
        let elements = self
            .iter()
            .map(|elem| elem.size_hint())
            .fold(Some(0usize), |acc, elem| if let (Some(acc), Some(elem)) = (acc, elem) {
                Some(acc + elem)
            } else {
                None
            });

        elements.map(|sz| sz + std::mem::size_of::<VecToBytesLenType>())
    }
}

impl<T: FromBytes> FromBytes for Vec<T> {
    fn parse<R: Buf>(mut buf: R) -> Result<Self, std::io::Error> {
        let len: VecToBytesLenType = buf.get_u32_le();
        (0..len)
            .map(|_| T::parse(&mut buf))
            .collect::<Result<Self, _>>()
    }
}
