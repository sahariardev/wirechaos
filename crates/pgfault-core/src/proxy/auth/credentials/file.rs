use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use rand::RngCore;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::proxy::auth::{
    credentials::{
        report::{ConfigError, ErrorBag},
        secret::derive_verifier,
        store::Snapshot,
    },
    verifier::{SecretFormatError, Verifier},
};

/// The plaintext YAML iteration count used when deriving a verifier from a
/// `password:` entry. It matches PostgreSQL's `scram_sha_256_iterations`.
pub const DEFAULT_ITERATIONS: u32 = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawUser {
    name: String,
    password: Option<String>,
    scram_secret: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawStoreFile {
    users: Vec<RawUser>,
}

/// Parse and validate a `users:` YAML document into a snapshot.
///
/// The input is copied into a zeroizing buffer before parsing so the raw text
/// does not outlive the load in freed memory.
pub(crate) fn snapshot_from_yaml(text: &str) -> Result<Snapshot, ConfigError> {
    let buffer = Zeroizing::new(text.to_owned());

    let raw_store_file: RawStoreFile = serde_yaml::from_str(&buffer)
        .map_err(|_| ConfigError::single("file", "invalid YAML user list"))?;

    let mut errors = ErrorBag::default();
    let mut users: HashMap<String, Arc<Verifier>> = HashMap::new();
    let mut seen: HashSet<String> = HashSet::new();

    if raw_store_file.users.is_empty() {
        errors.push(None, "users", "at least one user is required");
    }

    for mut user in raw_store_file.users {
        // Take the secret-bearing strings into zeroizing buffers immediately, so
        // the serde-allocated originals are overwritten when the iteration ends
        // (and on an early `?`/return).
        let password: Option<Zeroizing<String>> = user.password.take().map(Zeroizing::new);
        let scram_secret: Option<Zeroizing<String>> = user.scram_secret.take().map(Zeroizing::new);

        let mut name_ok = true;

        if user.name.is_empty() {
            errors.push(None, "name", "must not be empty");
            name_ok = false;
        }

        if user.name.contains('\0') {
            errors.push(Some(&user.name), "name", "must not contain NUL");
            name_ok = false;
        }

        if !seen.insert(user.name.clone()) {
            errors.push(Some(&user.name), "name", "duplicate user name");
            name_ok = false;
        }

        match (password.as_ref(), scram_secret.as_ref()) {
            (Some(password), None) => {
                if password.is_empty() {
                    errors.push(Some(&user.name), "password", "must not be empty");
                } else if name_ok {
                    let verifier = derive_verifier(password, &random_salt(), DEFAULT_ITERATIONS);
                    users.insert(user.name.clone(), Arc::new(verifier));
                }
            }
            (None, Some(scram_secret)) => match Verifier::from_pg_secret(scram_secret) {
                Ok(verifier) => {
                    if name_ok {
                        users.insert(user.name.clone(), Arc::new(verifier));
                    }
                }
                Err(error) => {
                    let (field, reason) = secret_reason(&error);
                    errors.push(Some(&user.name), field, reason);
                }
            },
            _ => {
                errors.push(
                    Some(&user.name),
                    "password",
                    "exactly one of `password` or `scram_secret` is required",
                );
            }
        }
    }

    errors.into_result()?;

    Ok(Snapshot::new(0, users))
}

fn secret_reason(err: &SecretFormatError) -> (&'static str, &'static str) {
    use SecretFormatError::*;
    (
        "scram_secret",
        match err {
            Md5 => "MD5 secrets are not supported; re-hash the role with scram-sha-256",
            UnsupportedScheme => "expected a SCRAM-SHA-256 secret",
            Syntax => "malformed secret",
            Iterations => "invalid iteration count",
            IterationsTooLow => "iteration count must be at least 4096",
            Base64 { .. } => "invalid base64",
            KeyLength { .. } => "each key must be exactly 32 bytes",
            SaltTooShort => "salt must be at least 8 bytes",
        },
    )
}

fn random_salt() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);

    salt
}
