//! Module defining traits for how rust types get serialized to bytes when transmitted

use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr}, borrow::Cow};

use bytes::{Buf, BufMut, BytesMut};
use chrono::{NaiveDateTime, Utc};

pub trait ByteWriter: BufMut + Sized {
    /// Write the byte representation of the given value to `self`, and return the bytes that were
    /// written, used to sign the encoded representation of `val`
    fn write_partial<'a, T: ToBytes>(&'a mut self, val: &T) -> Cow<'a, [u8]> {
        let buf = val.encode_to_vec();
        self.put_slice(&buf);
        Cow::Owned(buf)
    }
}

impl ByteWriter for Vec<u8> {
    fn write_partial<'a, T: ToBytes>(&'a mut self, val: &T) -> Cow<'a, [u8]> {
        let start_idx = self.len();
        val.encode(self);
        Cow::Borrowed(&self[start_idx..])
    }
}

impl<T: ByteWriter> ByteWriter for &mut T {}
impl ByteWriter for BytesMut {}

/// Trait to be implemented by all types that can be written to a byte buffer
pub trait ToBytes: Sized {
    /// Write the representation of this payload to a buffer of bytes
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError>;

    /// Provide the encoded size in bytes of this value
    fn size_hint(&self) -> usize { 0 }

    /// Write the full representation of [self] to a vec of bytes
    fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::<u8>::with_capacity(self.size_hint());
        self.encode(&mut buf);
        buf
    }
}

/// Trait implemented by all types that may be parsed from a byte buffer that is sent in a message
/// payload
pub trait FromBytes: Sized {
    /// Read bytes the given buffer (multi-byte words should be little endian) to create an
    /// instance of `Self`
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError>;

    /// Helper function to read an instance of `Self` without needing to create [untrusted] types
    fn decode_from_slice(slice: &[u8]) -> Result<Self, FromBytesError> {
        let mut reader = untrusted::Reader::new(untrusted::Input::from(slice));
        Self::decode(&mut reader)
    }
    
    /// Parse an instance of `Self` and return a tuple of the bytes that were parsed and the
    /// instance
    fn partial_decode_from_slice(slice: &[u8]) -> Result<(&[u8], Self), FromBytesError> {
        let mut reader = untrusted::Reader::new(untrusted::Input::from(slice));
        let (read, this) = reader.read_partial(Self::decode)?;
        Ok((read.as_slice_less_safe(), this))
    }
}


pub type LenType = u32;

/// Format: 
/// 4 byte length
/// Variable length data
impl<T: ToBytes> ToBytes for Vec<T> {
    fn encode<B: ByteWriter>(&self, buf: &mut B) -> Result<(), ToBytesError> {
        (self.len() as LenType).encode(buf);
        for elem in self.iter() {
            elem.encode(buf);
        }

        Ok(())
    }

    fn size_hint(&self) -> usize {
        let elements: usize = self
            .iter()
            .map(|elem| elem.size_hint())
            .sum();

        elements + std::mem::size_of::<LenType>()
    }
}

impl<T: FromBytes> FromBytes for Vec<T> {
    fn decode(buf: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let len: LenType = LenType::decode(buf)?;
        (0..len).map(|_| T::decode(buf)).collect::<Result<Self, _>>()
    }
}

macro_rules! integral_from_to_bytes {
    ($type:ty: $get_method_name:ident, $put_method_name:ident) => {
        impl ToBytes for $type {
            fn encode<B: ByteWriter>(&self, buf: &mut B) -> Result<(), ToBytesError> {
                buf.$put_method_name(*self);
                Ok(())
            }

            fn size_hint(&self) -> usize {
                std::mem::size_of::<Self>()
            }
        }

        impl FromBytes for $type {
            fn decode(buf: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
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
    fn encode<W: BufMut>(&self, _buf: &mut W) -> Result<(), ToBytesError> { Ok(()) }
    fn size_hint(&self) -> usize { 0 }
}

/// Errors that may occur when reading a value from a byte buffer
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

/// Errors that may occur when encoding a value to a byte buffer
#[derive(Debug, thiserror::Error)]
pub enum ToBytesError {
    #[error("Attempted to encode an invalid value: {0}")]
    InvalidValue(String),
}

impl From<untrusted::EndOfInput> for FromBytesError {
    fn from(value: untrusted::EndOfInput) -> Self {
        Self::EndOfInput(value)
    }
}

const IPVERSION_MARKER_V4: u8 = 4;
const IPVERSION_MARKER_V6: u8 = 6;

const fn ipaddr_tag(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => IPVERSION_MARKER_V4,
        IpAddr::V6(_) => IPVERSION_MARKER_V6,
    }
}

/// Format of general (IPv4 or IPv6) IP address:
/// ipversion - 1 byte - 4 for ipv4 and 6 for ipv6
/// addr - 4 or 16 bytes - based on ipversion
impl ToBytes for IpAddr {
    fn encode<B: ByteWriter>(&self, buf: &mut B) -> Result<(), ToBytesError> {
        ipaddr_tag(self).encode(buf)?;
        match self {
            Self::V4(v4addr) => {
                v4addr.encode(buf)
            }
            Self::V6(v6addr) => {
                v6addr.encode(buf)
            }
        }
    }

    fn size_hint(&self) -> usize {
        let sz = match self {
            Self::V4(addr) => addr.size_hint(),
            Self::V6(addr) => addr.size_hint(),
        };

        sz + ipaddr_tag(self).size_hint()
    }
}

impl FromBytes for IpAddr {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let marker = u8::decode(reader)?;
        Ok(match marker {
            IPVERSION_MARKER_V4 => Self::V4(Ipv4Addr::decode(reader)?),
            IPVERSION_MARKER_V6 => Self::V6(Ipv6Addr::decode(reader)?),
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
    fn encode<W: BufMut>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        buf.put_slice(&self.octets());
        Ok(())
    }

    fn size_hint(&self) -> usize { 4 }
}

impl FromBytes for Ipv4Addr {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
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
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        let octets = self.octets();
        buf.put_slice(&octets);
        Ok(())
    }

    fn size_hint(&self) -> usize { 16 }
}

impl FromBytes for Ipv6Addr {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
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
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        (self.as_bytes().len() as u32).encode(buf)?;
        buf.put_slice(&self.as_bytes());
        Ok(())
    }

    fn size_hint(&self) -> usize { self.as_bytes().len() + (self.len() as u32).size_hint() }
}

impl FromBytes for String {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let len = u32::decode(reader)?;
        let bytes = reader.read_bytes(len as usize)?;
        Ok(Self::from_utf8_lossy(bytes.as_slice_less_safe()).into_owned())
    }
}

impl<const N: usize> ToBytes for [u8; N] {
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        buf.put_slice(self.as_slice());
        Ok(())
    }

    fn size_hint(&self) -> usize { N }
}

impl<const N: usize> FromBytes for [u8; N] {
    fn decode(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
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
    fn encode<W: ByteWriter>(&self, buf: &mut W) -> Result<(), ToBytesError> {
        self.timestamp().encode(buf)
    }

    fn size_hint(&self) -> usize { self.timestamp().size_hint() }
}

impl FromBytes for chrono::DateTime<Utc> {
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
