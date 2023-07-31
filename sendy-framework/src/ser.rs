//! Module defining traits for how rust types get serialized to bytes when transmitted

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut};
use rsa::{
    pkcs8::{DecodePublicKey, EncodePublicKey},
    RsaPublicKey,
};

/// Trait to be implemented by all types that can be written to a byte buffer
pub trait ToBytes: Sized {
    /// Write the representation of this payload to a buffer of bytes
    fn write<W: BufMut>(&self, buf: W);

    /// Provide the encoded size in bytes of this value
    fn size_hint(&self) -> Option<usize> {
        None
    }
}

/// Trait implemented by all types that may be parsed from a byte buffer that is sent in a message
/// payload
pub trait FromBytes: Sized {
    /// Read bytes the given buffer (multi-byte words should be little endian) to create an
    /// instance of `Self`
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError>;
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

type RsaPublicKeyLenType = u16;

impl ToBytes for RsaPublicKey {
    fn write<W: BufMut>(&self, mut buf: W) {
        match self.to_public_key_der() {
            Ok(der) => {
                let bytes = der.as_bytes();
                buf.put_u16_le(bytes.len() as RsaPublicKeyLenType);
                buf.put_slice(bytes);
            }
            Err(e) => {
                log::error!("Failed to encode RSA public key as PKCS#8 DER: {}", e,);
            }
        }
    }

    fn size_hint(&self) -> Option<usize> {
        self.to_public_key_der()
            .ok()
            .map(|der| der.as_bytes().len())
    }
}

impl FromBytes for RsaPublicKey {
    fn parse(buf: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let len = RsaPublicKeyLenType::parse(buf)?;
        let bytes = buf.read_bytes(len as usize)?;

        match RsaPublicKey::from_public_key_der(bytes.as_slice_less_safe()) {
            Ok(pubkey) => Ok(pubkey),
            Err(e) => Err(FromBytesError::Parsing(e.to_string())),
        }
    }
}

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
            },
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
        }.map(|sz| sz + 1)
    }
}

impl FromBytes for IpAddr {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let marker = reader.read_byte()?;
        Ok(match marker {
            IPVERSION_MARKER_V4 => Self::V4(Ipv4Addr::parse(reader)?),
            IPVERSION_MARKER_V6 => Self::V6(Ipv6Addr::parse(reader)?),
            _ => return Err(FromBytesError::Parsing(format!("Unknown IP version marker {:X}", marker))),
        })
    }
}

/// Format of IPv4 address:
/// addr - 4 bytes - big endian address
impl ToBytes for Ipv4Addr {
    fn write<W: BufMut>(&self, buf: W) {
        let le = u32::from_le_bytes(self.octets());
        le.write(buf)
    }
}

impl FromBytes for Ipv4Addr {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let rd = [reader.read_byte()? ; 4];
        Ok(Self::from(rd))
    }
}

/// Format of IPv6 address:
/// addr - 16 bytes - big endian address
impl ToBytes for Ipv6Addr {
    fn write<W: BufMut>(&self, mut buf: W) {
        let mut octets = self.octets();
        buf.put_slice(&octets);
    }
    
    fn size_hint(&self) -> Option<usize> {
        Some(16)
    }
}

impl FromBytes for Ipv6Addr {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let rd = [reader.read_byte()? ; 16];
        Ok(Self::from(rd))
    }
}
