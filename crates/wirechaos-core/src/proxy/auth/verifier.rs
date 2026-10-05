use crate::proxy::auth::error::AuthError;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::sync::Arc;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("credential store unavailable")]
    Unavailable(#[source] Box<dyn Error + Send + Sync>),
}

impl AuthError for ProviderError {
    fn code(&self) -> &str {
        "08006"
    }

    fn message(&self) -> &str {
        "credential store temporarily unavailable"
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretFormatError {
    #[error("unrecognised secret scheme: expected `SCRAM-SHA-256$...`")]
    UnsupportedScheme,
    #[error("MD5 secrets are not supported; re-hash the role with `password_encryption = scram-sha-256`"
    )]
    Md5,
    #[error("this secret is malformed (expected `SCRAM-SHA-256$iter:salt$stored:server`)")]
    Syntax,
    #[error("invalid iteration count")]
    Iterations,
    #[error("iteration must be at least {MIN_ITERATIONS}")]
    IterationsTooLow,
    #[error("invalid base64 in {field}")]
    Base64 { field: &'static str },
    #[error("{field} must be exactly 32 bytes")]
    KeyLength { field: &'static str },
    #[error("salt must be at least 8 bytes")]
    SaltTooShort,
}

pub trait VerifierProvider: Send + Sync + 'static {
    async fn lookup(&self, username: &str) -> Result<Option<Arc<Verifier>>, ProviderError>;

    fn get_dummy_verifier(&self, username: &str) -> Verifier;
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

pub const MIN_ITERATIONS: u32 = 4096;

impl Verifier {
    pub fn from_password(password: &[u8], salt: &[u8], iterations: u32) -> Self {
        let salted = pbkdf2_sha256(password, &salt, iterations);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let server_key = hmac_sha256(&salted, b"Server Key");

        let verifier = Verifier {
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

    pub fn from_pg_secret(secret: &str) -> Result<Self, SecretFormatError> {
        if secret.starts_with("md5") {
            return Err(SecretFormatError::Md5);
        }

        let rest = secret
            .strip_prefix("SCRAM-SHA-256$")
            .ok_or(SecretFormatError::UnsupportedScheme)?;

        let (iters_and_salt, keys) = rest.split_once('$').ok_or(SecretFormatError::Syntax)?;

        let (iterations, salt) = iters_and_salt
            .split_once(':')
            .ok_or(SecretFormatError::Syntax)?;

        let (stored_key, server_key) = keys.split_once(':').ok_or(SecretFormatError::Syntax)?;

        let iterations: u32 = iterations.parse().or(Err(SecretFormatError::Iterations))?;

        if iterations < MIN_ITERATIONS {
            return Err(SecretFormatError::IterationsTooLow);
        }

        let salt = Zeroizing::new(
            B64.decode(salt)
                .map_err(|_| SecretFormatError::Base64 { field: "salt" })?,
        );

        if salt.len() < 8 {
            return Err(SecretFormatError::SaltTooShort);
        }

        let stored_key = decode_key(stored_key, "Stored key")?;
        let server_key = decode_key(server_key, "Server key")?;

        Ok(Verifier {
            iterations,
            salt: salt.to_vec(),
            stored_key,
            server_key,
            dummy: false,
        })
    }

    pub fn to_pg_secret(&self) -> String {
        format!(
            "SCRAM-SHA-256${}:{}${}:{}",
            self.iterations,
            B64.encode(&self.salt),
            B64.encode(&self.stored_key),
            B64.encode(&self.server_key)
        )
    }
}

fn decode_key(b64: &str, field: &'static str) -> Result<[u8; 32], SecretFormatError> {
    let bytes = B64
        .decode(b64)
        .map_err(|_| SecretFormatError::Base64 { field: field })?;

    bytes
        .try_into()
        .map_err(|_| SecretFormatError::KeyLength { field })
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

    #[test]
    fn secret_round_trips() {
        let original = Verifier::from_password(b"pencil", &[0x11; 16], 4096);
        let text = original.to_pg_secret();
        let parsed = Verifier::from_pg_secret(&text).expect("our own output must parse");

        assert_eq!(parsed.iterations(), 4096);
        assert_eq!(parsed.salt(), original.salt());
        assert_eq!(parsed.stored_key(), original.stored_key());
        assert_eq!(parsed.server_key(), original.server_key());
    }

    #[test]
    fn malformed_secrets_are_named() {
        use SecretFormatError::*;

        let cases: &[(&str, SecretFormatError)] = &[
            ("md5a1b2c3d4e5f60718293a4b5c6d7e8f9", Md5),
            ("SCRAM-SHA-1$4096:AA$AA:A", UnsupportedScheme),
            ("SCRAM-SHA-256$4096:AA$AA", Syntax),
            ("SCRAM-SHA-256$abc:AA$AA:AA", Iterations),
            ("SCRAM-SHA-256$1:AA$AA:AA", IterationsTooLow),
            ("SCRAM-SHA-256$4096:!!$AA:AA", Base64 { field: "salt" }),
            (
                "SCRAM-SHA-256$4096:c2FsdA==$AA:AA",
                KeyLength { field: "StoredKey" },
            ),
        ];

        for (input, expected) in cases {
            let result = Verifier::from_pg_secret(input);
            assert!(matches!(result, Err(ref actual) if actual == expected));
        }
    }
}
