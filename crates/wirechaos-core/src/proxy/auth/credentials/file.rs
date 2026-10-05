use rand::RngCore;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

use crate::proxy::auth::{
    credentials::{
        report::{ConfigError, ErrorBag},
        store::Snapshot,
    },
    verifier::{SecretFormatError, Verifier},
};

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

pub(crate) fn snapshot_from_yaml(text: &str) -> Result<Snapshot, ConfigError> {
    let raw_store_file: RawStoreFile =
        serde_yaml::from_str(text).map_err(|_| ConfigError::single("file", "invalid yaml"))?;

    let mut error_bag = ErrorBag::default();
    let mut users: HashMap<String, Arc<Verifier>> = HashMap::new();

    if raw_store_file.users.is_empty() {
        error_bag.push(None, "users", "At least one user is required");
    }

    for user in raw_store_file.users {
        match validate_user(&user, &mut users) {
            Err((field, reason)) => {
                error_bag.push(Some(&user.name), field, reason);
            }
            _ => {}
        }
    }

    error_bag.into_result()?;
    let snapshot = Snapshot::new(0, users);
    Ok(snapshot)
}

fn validate_user(
    user: &RawUser,
    users: &mut HashMap<String, Arc<Verifier>>,
) -> Result<(), (&'static str, &'static str)> {
    if user.name.is_empty() {
        return Err(("name", "must not be empty"));
    }

    if user.name.contains('\0') {
        return Err(("name", "must not contain null"));
    }

    if users.contains_key(&user.name) {
        return Err(("name", "duplicate user name"));
    }

    let verifier = match (&user.password, &user.scram_secret) {
        (Some(password), None) => {
            if password.is_empty() {
                return Err(("password", "must not be empty"));
            }

            Verifier::from_password(password.as_bytes(), &random_salt(), 4096)
        }
        (None, Some(scram_secret)) => {
            Verifier::from_pg_secret(&scram_secret).map_err(|error| secret_reason(&error))?
        }

        _ => {
            return Err((
                "password",
                "exactly one of `password` or `scram_secret` is required",
            ))
        }
    };

    users.insert(user.name.clone(), Arc::new(verifier));

    Ok(())
}

fn secret_reason(err: &SecretFormatError) -> (&'static str, &'static str) {
    use SecretFormatError::*;
    (
        "scram_secret",
        match err {
            Md5 => "MD5 secret are not supported (rehash with scram-sha-256)",
            UnsupportedScheme => "expected scram-sha-256",
            Syntax => "malformed secret",
            Iterations => "invalid iteration count",
            IterationsTooLow => "iteration must be atleast 4096",
            Base64 { .. } => "invalid base64",
            KeyLength { .. } => "key must be 32 bytes",
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
