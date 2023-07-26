use rsa::{pkcs1v15::SigningKey, sha2::Sha256};

/// State for the host node
pub struct Context {
    pub signature: SigningKey<Sha256>,
}
