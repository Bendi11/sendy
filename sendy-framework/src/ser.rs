//! Module defining traits for how rust types get serialized to bytes when transmitted

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut};
use chrono::{NaiveDateTime, Utc};

/// Trait to be implemented by all types that can be written to a byte buffer
pub trait ToBytes: Sized {
    /// Write the representation of this payload to a buffer of bytes
    fn write<W: BufMut>(&self, buf: W);

    /// Provide the encoded size in bytes of this value
    fn size_hint(&self) -> Option<usize> {
        None
    }

    /// Write the full representation of [self] to a vec of bytes
    fn write_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::<u8>::with_capacity(self.size_hint().unwrap_or(0));
        self.write(&mut buf);
        buf
    }
}

/// Trait implemented by all types that may be parsed from a byte buffer that is sent in a message
/// payload
pub trait FromBytes: Sized {
    /// Read bytes the given buffer (multi-byte words should be little endian) to create an
    /// instance of `Self`
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError>;

    /// Helper function to read an instance of [self] without needing to create [untrusted] types
    fn read_from_slice(slice: &[u8]) -> Result<Self, FromBytesError> {
        let mut reader = untrusted::Reader::new(untrusted::Input::from(slice));
        Self::parse(&mut reader)
    }
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
            .fold(Some(0usize), |acc, elem| {
                if let (Some(acc), Some(elem)) = (acc, elem) {
                    Some(acc + elem)
                } else {
                    None
                }
            });

        elements.map(|sz| sz + std::mem::size_of::<VecToBytesLenType>())
    }
}

impl<T: FromBytes> FromBytes for Vec<T> {
    fn parse(buf: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let len: VecToBytesLenType = VecToBytesLenType::parse(buf)?;
        (0..len).map(|_| T::parse(buf)).collect::<Result<Self, _>>()
    }
}

macro_rules! integral_from_to_bytes {
    ($type:ty: $get_method_name:ident, $put_method_name:ident) => {
        impl ToBytes for $type {
            fn write<B: BufMut>(&self, mut buf: B) {
                buf.$put_method_name(*self)
            }

            fn size_hint(&self) -> Option<usize> {
                Some(std::mem::size_of::<Self>())
            }
        }

        impl FromBytes for $type {
            fn parse(buf: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
                let bytes = buf.read_bytes(std::mem::size_of::<Self>())?;
                Ok(bytes.as_slice_less_safe().$get_method_name())
            }
        }
    };
}

integral_from_to_bytes! {u8: get_u8, put_u8}
integral_from_to_bytes! {u16: get_u16_le, put_u16_le}
integral_from_to_bytes! {u32: get_u32_le, put_u32_le}
integral_from_to_bytes! {u64: get_u64_le, put_u64_le}

integral_from_to_bytes! {i8: get_i8, put_i8}
integral_from_to_bytes! {i16: get_i16_le, put_i16_le}
integral_from_to_bytes! {i32: get_i32_le, put_i32_le}
integral_from_to_bytes! {i64: get_i64_le, put_i64_le}

impl ToBytes for () {
    fn write<W: BufMut>(&self, _buf: W) {}
    fn size_hint(&self) -> Option<usize> {
        Some(0)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FromBytesError {
    /// Error originating from the [untrusted] byte readers
    #[error("Unexpected end of input")]
    EndOfInput(untrusted::EndOfInput),
    /// Parsing from messages should not be recoverable, so error messages can be stored as strings
    /// to be displayed on the frontend
    #[error("{0}")]
    Parsing(String),
}

impl From<untrusted::EndOfInput> for FromBytesError {
    fn from(value: untrusted::EndOfInput) -> Self {
        Self::EndOfInput(value)
    }
}

const IPVERSION_MARKER_V4: u8 = 4;
const IPVERSION_MARKER_V6: u8 = 6;

/// Format of general (IPv4 or IPv6) IP address:
/// ipversion - 1 byte - 4 for ipv4 and 6 for ipv6
/// addr - 4 or 16 bytes - based on ipversion
impl ToBytes for IpAddr {
    fn write<B: BufMut>(&self, mut buf: B) {
        match self {
            Self::V4(v4addr) => {
                buf.put_u8(IPVERSION_MARKER_V4);
                v4addr.write(buf);
            }
            Self::V6(v6addr) => {
                buf.put_u8(IPVERSION_MARKER_V6);
                v6addr.write(buf);
            }
        }
    }

    fn size_hint(&self) -> Option<usize> {
        match self {
            Self::V4(addr) => addr.size_hint(),
            Self::V6(addr) => addr.size_hint(),
        }
        .map(|sz| sz + 1)
    }
}

impl FromBytes for IpAddr {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let marker = reader.read_byte()?;
        Ok(match marker {
            IPVERSION_MARKER_V4 => Self::V4(Ipv4Addr::parse(reader)?),
            IPVERSION_MARKER_V6 => Self::V6(Ipv6Addr::parse(reader)?),
            _ => {
                return Err(FromBytesError::Parsing(format!(
                    "Unknown IP version marker {:X}",
                    marker
                )))
            }
        })
    }
}

/// Format of IPv4 address:
/// addr - 4 bytes - big endian address
impl ToBytes for Ipv4Addr {
    fn write<W: BufMut>(&self, mut buf: W) {
        buf.put_slice(&self.octets());
    }
}

impl FromBytes for Ipv4Addr {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let mut buf = [0u8; 4];
        for idx in 0..buf.len() {
            buf[idx] = reader.read_byte()?;
        }
        Ok(Self::from(buf))
    }
}

/// Format of IPv6 address:
/// addr - 16 bytes - big endian address
impl ToBytes for Ipv6Addr {
    fn write<W: BufMut>(&self, mut buf: W) {
        let octets = self.octets();
        buf.put_slice(&octets);
    }

    fn size_hint(&self) -> Option<usize> {
        Some(16)
    }
}

impl FromBytes for Ipv6Addr {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let mut buf = [0u8; 16];
        for idx in 0..buf.len() {
            buf[idx] = reader.read_byte()?;
        }
        Ok(Self::from(buf))
    }
}

/// Format of string:
/// len - 4 bytes - [u32](std::u32)
/// bytes - `len` bytes
impl ToBytes for String {
    fn write<W: BufMut>(&self, mut buf: W) {
        (self.as_bytes().len() as u32).write(&mut buf);
        buf.put_slice(&self.as_bytes())
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.as_bytes().len())
    }
}

impl FromBytes for String {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let len = u32::parse(reader)?;
        let bytes = reader.read_bytes(len as usize)?;
        Ok(Self::from_utf8_lossy(bytes.as_slice_less_safe()).into_owned())
    }
}

impl<const N: usize> ToBytes for [u8; N] {
    fn write<W: BufMut>(&self, mut buf: W) {
        buf.put_slice(self.as_slice())
    }

    fn size_hint(&self) -> Option<usize> {
        Some(N)
    }
}

impl<const N: usize> FromBytes for [u8; N] {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let mut this = [0u8; N];
        for idx in 0..N {
            this[idx] = reader.read_byte()?;
        }

        Ok(this)
    }
}

/// Format:
/// UNIX timestamp - 8 bytes
impl ToBytes for chrono::DateTime<Utc> {
    fn write<W: BufMut>(&self, buf: W) {
        self.timestamp().write(buf)
    }

    fn size_hint(&self) -> Option<usize> {
        self.timestamp().size_hint()
    }
}

impl FromBytes for chrono::DateTime<Utc> {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let ts = i64::parse(reader)?;
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
