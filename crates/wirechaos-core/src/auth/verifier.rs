use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub trait VerifierProvider {
    fn get(&self, username: &str) -> Result<Verifier, Box<dyn std::error::Error>>;
}

#[derive(Clone)]
pub struct Verifier {
    pub iterations: u32,
    pub salt: Vec<u8>,
    pub stored_key: Vec<u8>,
    pub server_key: Vec<u8>,
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
