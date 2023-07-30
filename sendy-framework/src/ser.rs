//! Module defining traits for how rust types get serialized to bytes when transmitted

use bytes::{BufMut, Buf};
use rsa::{RsaPublicKey, pkcs8::{EncodePublicKey, DecodePublicKey}};

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
            fn parse<B: Buf>(mut buf: B) -> Result<Self, std::io::Error> {
                Ok(buf.$get_method_name())
            }
        }
    };
}

integral_from_to_bytes!{u8: get_u8, put_u8}
integral_from_to_bytes!{u16: get_u16_le, put_u16_le}
integral_from_to_bytes!{u32: get_u32_le, put_u32_le}
integral_from_to_bytes!{u64: get_u64_le, put_u64_le}


integral_from_to_bytes!{i8: get_i8, put_i8}
integral_from_to_bytes!{i16: get_i16_le, put_i16_le}
integral_from_to_bytes!{i32: get_i32_le, put_i32_le}
integral_from_to_bytes!{i64: get_i64_le, put_i64_le}

type RsaPublicKeyLen = u16;

impl ToBytes for RsaPublicKey {
    fn write<W: BufMut>(&self, mut buf: W) {
        match self.to_public_key_der() {
            Ok(der) => {
                let bytes = der.as_bytes();
                buf.put_u16_le(bytes.len() as RsaPublicKeyLen);
                buf.put_slice(bytes);
            },
            Err(e) => {
                log::error!(
                    "Failed to encode RSA public key as PKCS#8 DER: {}",
                    e,
                );
            }
        }
    }

    fn size_hint(&self) -> Option<usize> {
        self
            .to_public_key_der()
            .ok()
            .map(|der| der.as_bytes().len())
    }
}

impl FromBytes for RsaPublicKey {
    fn parse<R: Buf>(mut buf: R) -> Result<Self, std::io::Error> {
        let len = buf.get_u16_le();
        let bytes = buf.copy_to_bytes(len as usize);

        match RsaPublicKey::from_public_key_der(&bytes) {
            Ok(pubkey) => Ok(pubkey),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)),
        }
    }
}
