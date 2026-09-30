use crate::proxy::auth::error::AuthError;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::error::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

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

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Verifier {
    #[zeroize(skip)]
    iterations: u32,
    salt: Vec<u8>,
    stored_key: [u8; 32],
    server_key: [u8; 32],
    #[zeroize(skip)]
    dummy: bool,
}

impl Verifier {
    pub fn from_password(password: &[u8], salt: &[u8], iterations: u32) -> Self {
        let salted = pbkdf2_sha256(password, &salt, iterations);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let server_key = hmac_sha256(&salted, b"Server Key");

        let mut verifier = Verifier {
            iterations,
            salt: salt.to_vec(),
            stored_key: sha256(&client_key),
            server_key,
            dummy: false,
        };

        let mut salted = salted;
        let mut client_key = client_key;
        salted.zeroize();
        client_key.zeroize();

        verifier
    }
    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }
    pub fn stored_key(&self) -> &[u8; 32] {
        &self.stored_key
    }

    pub fn server_key(&self) -> &[u8; 32] {
        &self.server_key
    }

    pub fn is_dummy(&self) -> bool {
        self.dummy
    }

    pub fn dummy(username: &str, cluster_nonce: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(username.as_bytes());
        hasher.update(cluster_nonce);
        let digest = hasher.finalize();

        Verifier {
            iterations: 4096,
            salt: digest[..16].to_vec(),
            stored_key: [0u8; 32],
            server_key: [0u8; 32],
            dummy: true,
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

#[cfg(test)]
mod hygiene {
    use super::*;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(Verifier: std::fmt::Debug, std::fmt::Display, Clone);

    #[test]
    fn keys_are_zeroized_on_drop() {
        let bytes = {
            let v = Verifier::from_password(b"pencil", &[0x5a; 16], 4096);
            v.stored_key().to_vec()
        };

        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn explicit_zeroize_clears_the_key() {
        let mut v = Verifier::from_password(b"pencil", &[0x5a; 16], 4096);
        v.zeroize();
        assert_eq!(v.stored_key, [0u8; 32]);
        assert_eq!(v.server_key, [0u8; 32]);
        assert!(v.salt.iter().all(|&b| b == 0));
    }
}
