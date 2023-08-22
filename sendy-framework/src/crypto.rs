use rsa::pkcs1v15::{SigningKey, DecryptingKey};
use sha2::Sha256;



/// Private keys used to authenticate and exhcange symmetric encryption keys 
#[derive(Debug)]
pub struct PrivateKeychain {
    /// Key used to sign messages to verify the authenticity of a resource
    pub authentication: SigningKey<Sha256>,
    /// Key used to decrypt private messages
    pub encryption: DecryptingKey,
}
