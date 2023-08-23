use rsa::pkcs1v15::Signature;


pub struct Signed<T> {
    value: T,
    signature: Signature,
    valid: bool,
}
