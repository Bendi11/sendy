use std::net::IpAddr;

use bytes::BufMut;
use rsa::{sha2::Sha256, pkcs1v15::{DecryptingKey, SigningKey, VerifyingKey, Signature}, RsaPublicKey, pkcs8::{EncodePublicKey, DecodePublicKey}, signature::{SignatureEncoding, Signer}, RsaPrivateKey};

use crate::ser::{FromBytes, ToBytes, FromBytesError};


/// A collection of public **and private** cryptographic keys used to sign
/// and decrypt messages, this should never be shared and does not implement to and from Bytes
#[derive(Debug)]
pub struct PrivateKeychain {
    /// RSA keys used to sign messages that have been sent
    pub(crate) auth: SigningKey<Sha256>,
    /// RSA keys used to encrypt and decrypt messages for symmetric session key transfers
    pub(crate) enc: RsaPrivateKey,
}

/// A collection of public keys that are used to verify digitally signed messages and encrypt
/// messages, this must be sent to every peer
#[derive(Clone, Debug)]
pub struct PublicKeychain {
    /// Verification key that can authenticate signed messages
    pub auth: VerifyingKey<Sha256>,
    /// Public encryption key
    pub enc: RsaPublicKey,
}

/// A signed certificate that states the IP address that owns a set of public keys used for
/// authorization and encryption
#[derive(Clone, Debug)]
pub struct SignedCertificate {
    /// The public keychain and owner IP address, natively accessible from Rust code
    repr: UnsignedCertificate,
    /// Cached encoded version of this certificate from when the signature was created or the
    /// message was received
    encoded: Box<[u8]>,
    /// The signature that should have been generated by a trusted private key
    signature: Signature,
}

/// A certificate claiming ownership over a set of public keys that has not yet been signed by a
/// private key
///
/// Format:
/// ([PublicKeychain])
/// ([IpAddr])
#[derive(Clone, Debug)]
pub struct UnsignedCertificate {
    /// The keys that the IP address in this certificate claims
    keys: PublicKeychain,
    /// The IP address of the peer that is claiming these keys
    owner: IpAddr,
}

impl PrivateKeychain {
    /// Create a new private keychain from RSA private keys for authentication and encryption
    pub fn new(auth: RsaPrivateKey, enc: RsaPrivateKey) -> Self {
        Self {
            auth: SigningKey::new(auth),
            enc,
        }
    }
    
    /// Get a public keychain that corresponds to the private keys held in [self]
    pub fn public(&self) -> PublicKeychain {
        use rsa::signature::Keypair;

        PublicKeychain {
            auth: self.auth.verifying_key(),
            enc: self.enc.to_public_key(),
        }
    }
    
    /// Create a self-signed certificate stating that the given IP owns the public keys that
    /// correspond to the private keys stored in [self]
    pub fn certificate(&self, owner: IpAddr) -> SignedCertificate {
        let cert = UnsignedCertificate::new(
            self.public(),
            owner,
        );

        cert.sign(&self.auth)
    }
}

impl SignedCertificate {
    /// Verify that the given signed certificate is valid
    pub fn verify(&self, key: &VerifyingKey<Sha256>) -> bool {
        use rsa::signature::Verifier;

        key.verify(&self.encoded, &self.signature).is_ok()
    }
    
    /// Get the certificate data from this signed certificate
    pub const fn cert(&self) -> &UnsignedCertificate {
        &self.repr
    }
    
    /// Get the signature that authenticates the certificate
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl UnsignedCertificate {
    /// Create a new certificate which claims that `owner` owns `keys`
    pub const fn new(keys: PublicKeychain, owner: IpAddr) -> Self {
        Self { keys, owner }
    }

    /// Turn this [UnsignedCertificate] into a [SignedCertificate] by signing the encoded
    /// representation of this certificate and saving it
    pub fn sign(self, key: &impl Signer<Signature>) -> SignedCertificate {
        let mut encoded = vec![];
        self.write(&mut encoded);
        let signature = key.sign(&encoded);

        SignedCertificate {
            repr: self,
            encoded: encoded.into_boxed_slice(),
            signature,
        }
    }
    
    /// Get the public keys that the owner is claiming
    pub const fn keychain(&self) -> &PublicKeychain {
        &self.keys
    }
    
    /// Get the IP address of owner of these public keys
    pub const fn owner(&self) -> &IpAddr {
        &self.owner
    }
}

/// Format:
/// ([cert](UnsignedCertificate), [signature](Vec<u8>))
impl ToBytes for SignedCertificate {
    fn write<W: BufMut>(&self, mut buf: W) {
        (self.encoded.len() as u16).write(&mut buf);
        buf.put_slice(&self.encoded);
        self.signature.write(&mut buf);
    }

    fn size_hint(&self) -> Option<usize> {
        self.repr.size_hint()
            .zip(self.signature.size_hint())
            .zip((self.encoded.len() as u16).size_hint())
            .map(|((sz1, sz2), sz3)| sz1 + sz2 + sz3)
    }
}

impl FromBytes for SignedCertificate {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let len = u16::parse(reader)?;
        let slice = reader.read_bytes(len as usize)?;
        let encoded = Box::from(slice.as_slice_less_safe());
        let repr = UnsignedCertificate::parse(&mut untrusted::Reader::new(slice))?;

        let signature = Signature::parse(reader)?;

        Ok(Self {
            repr,
            encoded,
            signature,
        })
    }
}

/// Format: [[len](std::u16) - 2 bytes, [bytes](Vec<u8>)]
impl ToBytes for Signature {
    fn write<W: BufMut>(&self, mut buf: W) {
        let bytes = self.to_bytes();
        (bytes.len() as u16).write(&mut buf);
        buf.put_slice(&bytes);
    }

    fn size_hint(&self) -> Option<usize> {
        (self.encoded_len() as u16)
            .size_hint()
            .map(|sz| sz + self.encoded_len())
    }
}

impl FromBytes for Signature {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let len = u16::parse(reader)?;
        let buf = reader.read_bytes(len as usize)?;
        Self::try_from(buf.as_slice_less_safe())
            .map_err(|e| FromBytesError::Parsing(format!("Failed to parse RSA signature: {}", e)))
    }
}

/// Format: ([keys](PublicKeychain), [owner](IpAddr))
impl ToBytes for UnsignedCertificate {
    fn write<W: bytes::BufMut>(&self, mut buf: W) {
        self.keys.write(&mut buf);
        self.owner.write(&mut buf);
    }

    fn size_hint(&self) -> Option<usize> {
        self.keys.size_hint()
            .and_then(|keysz| self.owner.size_hint().map(|sz| sz + keysz))
    }
}

impl FromBytes for UnsignedCertificate {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        Ok(Self {
            keys: PublicKeychain::parse(reader)?,
            owner: IpAddr::parse(reader)?,
        })
    }
}

/// Format: ([authkey](VerifyingKey), [encryptkey](RsaPublicKey))
impl ToBytes for PublicKeychain {
    fn write<W: BufMut>(&self, mut buf : W) {
        self.auth.write(&mut buf);
        self.enc.write(&mut buf);
    }

    fn size_hint(&self) -> Option<usize> {
        self.auth.size_hint()
            .and_then(|authsz| self.enc.size_hint().map(|sz| sz + authsz))
    }
}

impl FromBytes for PublicKeychain {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        Ok(Self {
            auth: VerifyingKey::parse(reader)?,
            enc: RsaPublicKey::parse(reader)?,
        })
    }
}

/// Format of RsaPublicKey:
///
/// len - 2 bytes - length of ASN.1 DER-encoded RSA public key
/// der - variable bytes determined by len
impl ToBytes for RsaPublicKey {
    fn write<W: BufMut>(&self, mut buf: W) {
        let der = match self.to_public_key_der() {
            Ok(der) => der,
            Err(e) => {
                log::error!("Failed to encode RSA public key as DER: {}", e);
                0u16.write(buf);
                return
            }
        };
        
        let der = der.as_bytes();
        (der.len() as u16).write(&mut buf);
        buf.put_slice(der);
    }
}

impl FromBytes for RsaPublicKey {
    fn parse(buf: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        let len = u16::parse(buf)?;
        println!("len: {}", len);
        let bytes = buf.read_bytes(len as usize)?;

        match RsaPublicKey::from_public_key_der(bytes.as_slice_less_safe()) {
            Ok(pubkey) => Ok(pubkey),
            Err(e) => Err(FromBytesError::Parsing(e.to_string())),
        }
    }
}

/// Same format as [RsaPublicKey]
impl<D: rsa::sha2::Digest> ToBytes for VerifyingKey<D> {
    fn write<W: bytes::BufMut>(&self, buf: W) {
        RsaPublicKey::write(self.as_ref(), buf)
    }

    fn size_hint(&self) -> Option<usize> {
        RsaPublicKey::size_hint(self.as_ref())
    }
}

impl FromBytes for VerifyingKey<Sha256> {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, FromBytesError> {
        Ok(Self::new(RsaPublicKey::parse(reader)?))
    }
}
