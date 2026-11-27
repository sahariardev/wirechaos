//! The `auth_query` credential source (the pgbouncer pattern).
//!
//! The proxy opens a short-lived connection as a dedicated lookup role and runs
//! a parameterised query that returns `(usename, passwd)`. The lookup role is
//! expected to be backed by a `SECURITY DEFINER` function scoped to one row, so
//! the proxy never needs superuser rights.
//!
//! Failures fall into three buckets and must not be flattened:
//!
//! * a row with a SCRAM secret → a verifier;
//! * no row → `Ok(None)` (the caller runs the mock exchange);
//! * the connection or query failed → `ProviderError::Unavailable`, which the
//!   client sees as `08006`, never as a wrong password.
//!
//! The configuration type is always compiled (it is pure data); the SQL driver
//! and [`AuthQuerySource`] are gated behind the `auth-query` feature so the data
//! plane's dependency tree stays small by default.

use std::time::Duration;

use zeroize::Zeroizing;

/// How long a "no such user" answer is remembered. Short on purpose: it blunts
/// enumeration without hiding a user that was just provisioned.
pub const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(5);

/// How long a successfully read secret is remembered.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60);

/// A fully resolved `auth_query` configuration.
///
/// The lookup password has already been resolved from its environment variable
/// by the config loader, so this type holds the only plaintext in the store —
/// and it is zeroized on drop.
pub struct AuthQueryConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Zeroizing<String>,
    pub database: String,
    pub query: String,
    pub cache_ttl: Duration,
    pub negative_ttl: Duration,
    pub max_entries: usize,
}

impl AuthQueryConfig {
    /// Reject a query that is not exactly one `$1` placeholder.
    ///
    /// Checking `query.matches("$1")` is not enough: `$1, $2` contains one
    /// `$1` but binds two parameters, so the query is scanned for every `$N`.
    pub fn validate(query: &str) -> Result<(), &'static str> {
        let bytes = query.as_bytes();
        let mut placeholders = Vec::new();
        let mut i = 0;

        while i < bytes.len() {
            if bytes[i] != b'$' {
                i += 1;
                continue;
            }

            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }

            if end > start {
                if let Ok(number) = query[start..end].parse::<u32>() {
                    placeholders.push(number);
                }
                i = end;
            } else {
                i += 1;
            }
        }

        if placeholders.len() != 1 {
            return Err("query must contain exactly one placeholder");
        }

        if placeholders[0] != 1 {
            return Err("the placeholder must be $1 (the requested user name)");
        }

        Ok(())
    }
}

#[cfg(feature = "auth-query")]
mod sql {
    use std::sync::Arc;
    use std::time::Instant;

    use tokio::sync::Mutex;
    use tokio_postgres::{Client, NoTls};

    use crate::proxy::auth::{
        credentials::cache::LookupCache,
        verifier::{ProviderError, Verifier},
    };

    use super::AuthQueryConfig;

    pub struct AuthQuerySource {
        config: AuthQueryConfig,
        cache: Mutex<LookupCache>,
        client: Mutex<Option<Client>>,
    }

    impl AuthQuerySource {
        pub fn new(config: AuthQueryConfig) -> Self {
            let cache = LookupCache::with_capacity(
                config.cache_ttl,
                config.negative_ttl,
                config.max_entries,
            );

            Self {
                config,
                cache: Mutex::new(cache),
                client: Mutex::new(None),
            }
        }

        /// Establish the lookup connection eagerly, so a startup-time outage can
        /// be reported by `/readyz` instead of by the first login (`lazy: false`).
        pub async fn preflight(&self) -> Result<(), ProviderError> {
            self.ensure_connected().await
        }

        /// Forget one user's cached entry, for the control plane's "forget user"
        /// call after an out-of-band `ALTER ROLE`.
        pub async fn forget(&self, username: &str) {
            self.cache.lock().await.forget(username);
        }

        pub async fn lookup(&self, username: &str) -> Result<Option<Arc<Verifier>>, ProviderError> {
            let now = Instant::now();

            if let Some(cached) = self.cache.lock().await.get(username, now) {
                return Ok(cached);
            }

            let row = self.query_backend(username).await?;

            let mut cache = self.cache.lock().await;

            match row {
                Some(secret) => {
                    let verifier = Verifier::from_pg_secret(&secret)
                        .map_err(|error| ProviderError::Unavailable(Box::new(error)))?;
                    let verifier = Arc::new(verifier);

                    cache.insert_positive(username, verifier.clone(), now);
                    Ok(Some(verifier))
                }
                None => {
                    cache.insert_negative(username, now);
                    Ok(None)
                }
            }
        }

        async fn ensure_connected(&self) -> Result<(), ProviderError> {
            let mut guard = self.client.lock().await;

            if guard.is_some() {
                return Ok(());
            }

            let mut config = tokio_postgres::Config::new();
            config
                .host(&self.config.host)
                .port(self.config.port)
                .user(&self.config.user)
                .dbname(&self.config.database)
                .password(self.config.password.as_str());

            let (client, connection) = config.connect(NoTls).await.map_err(unavailable)?;

            // The connection future drives the socket; it must be polled for the
            // client to make progress. The client is dropped via the mutex on
            // replacement, which ends the future.
            tokio::spawn(async move {
                if let Err(error) = connection.await {
                    tracing::warn!(error = %error, "auth_query lookup connection ended");
                }
            });

            *guard = Some(client);
            Ok(())
        }

        async fn query_backend(&self, username: &str) -> Result<Option<String>, ProviderError> {
            self.ensure_connected().await?;

            let mut guard = self.client.lock().await;
            let client = guard
                .as_ref()
                .ok_or_else(|| unavailable_text("auth_query client unavailable"))?;

            let row = client
                .query_opt(self.config.query.as_str(), &[&username])
                .await;

            match row {
                Ok(Some(row)) => row.try_get::<_, Option<String>>(1).map_err(unavailable),
                Ok(None) => Ok(None),
                Err(error) => {
                    // Drop the broken client so the next lookup reconnects instead
                    // of failing forever against a dead socket.
                    *guard = None;
                    Err(unavailable(error))
                }
            }
        }
    }

    fn unavailable(error: impl std::error::Error + Send + Sync + 'static) -> ProviderError {
        ProviderError::Unavailable(Box::new(error))
    }

    fn unavailable_text(message: &'static str) -> ProviderError {
        ProviderError::Unavailable(Box::new(std::io::Error::other(message)))
    }
}

#[cfg(feature = "auth-query")]
pub use sql::AuthQuerySource;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exactly_one_dollar_one_placeholder() {
        assert!(AuthQueryConfig::validate("SELECT usename, passwd FROM lookup($1)").is_ok());
        assert!(AuthQueryConfig::validate("SELECT usename, passwd FROM lookup()").is_err());
        assert!(AuthQueryConfig::validate("SELECT * FROM lookup($1, $2)").is_err());
        assert!(AuthQueryConfig::validate("SELECT * FROM lookup($2)").is_err());
        assert!(AuthQueryConfig::validate("SELECT '$1' FROM lookup($1)").is_err());
    }
}
