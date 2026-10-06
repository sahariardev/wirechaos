//! Credentials, credential sources, and secret hygiene (task 3).
//!
//! The module is organised around one contract (see
//! [`crate::proxy::auth::verifier::VerifierProvider`]) with three outcomes:
//! *here is the verifier*, *I have no such user*, and *I am broken*. A store is
//! an immutable snapshot behind an atomic swap, so readers never block and a
//! reload is all-or-nothing.

mod auth_query;
mod cache;
mod config;
mod file;
mod metrics;
mod report;
mod secret;
mod store;

#[cfg(feature = "auth-query")]
pub use auth_query::AuthQuerySource;
pub use auth_query::{AuthQueryConfig, DEFAULT_CACHE_TTL, NEGATIVE_CACHE_TTL};
pub use cache::{LookupCache, DEFAULT_MAX_ENTRIES};
pub use config::{AuthQueryFileConfig, CredentialsConfig, SourceKind, WirechaosConfig};
pub use metrics::{CredentialMetrics, LookupResult};
pub use report::ConfigError;
pub use secret::{derive_verifier, prepare_password};
pub use store::{CredentialStore, ReloadHandle, ReloadReport, Snapshot, Source};

/// Derive a PostgreSQL SCRAM secret from a plaintext password.
///
/// This is the body of the `wirechaos hash-password` subcommand: the same
/// material can be installed in `pg_authid.rolpassword` and in a `users.yaml`
/// `scram_secret:` entry, which is what makes salt-reuse mode work.
pub fn hash_password(password: &str, iterations: u32) -> String {
    let salt: [u8; 16] = rand::random();
    derive_verifier(password, &salt, iterations).to_pg_secret()
}
