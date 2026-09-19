use crate::proxy::auth::error::AuthError;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::error::Error;

#[derive(Debug)]
pub enum ProviderError {}
impl Error for ProviderError {}

impl AuthError for ProviderError {
    fn code(&self) -> &str {
        "08006"
    }

    fn message(&self) -> &str {
        "temporarily unavailable"
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

pub trait VerifierProvider {
    fn lookup(&self, username: &str) -> Result<Option<Verifier>, ProviderError>;
    fn get_dummy_verifier(&self) -> Result<Verifier, ProviderError>;
}

#[derive(Clone)]
pub struct Verifier {
    pub iterations: u32,
    pub salt: Vec<u8>,
    pub stored_key: Vec<u8>,
    pub server_key: Vec<u8>,
    pub dummy: bool
}

impl Verifier {
    pub fn from_password(password: &str, salt: Vec<u8>, iterations: u32) -> Self {
        let salted = pbkdf2_sha256(password.as_bytes(), &salt, iterations);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let stored_key = sha256(&client_key);
        let server_key = hmac_sha256(&salted, b"Server Key");

        Verifier {
            iterations,
            salt,
            stored_key: stored_key.to_vec(),
            server_key: server_key.to_vec(),
            dummy: false
        }
    }
}

pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut out);
    out
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    // HMAC accepts a key of any length, so this cannot fail. The lint is allowed
    // here rather than propagated because threading a `Result` through every SCRAM
    // code path for an impossible error would obscure the real failure modes
    // (bad proof, bad nonce) that callers must actually handle.
    #[allow(clippy::expect_used)]
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC accepts a key of any length, so this cannot fail");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(input);
    h.finalize().into()
}
