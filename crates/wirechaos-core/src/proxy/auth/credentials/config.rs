use std::path::PathBuf;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[cfg(feature = "auth-query")]
use crate::proxy::auth::credentials::{
    auth_query::AuthQuerySource,
    store::{Snapshot, Source},
};
use crate::proxy::auth::credentials::{
    auth_query::{AuthQueryConfig, DEFAULT_CACHE_TTL, NEGATIVE_CACHE_TTL},
    cache::DEFAULT_MAX_ENTRIES,
    report::ConfigError,
    store::CredentialStore,
};

/// The `credentials.source` selector.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    #[default]
    File,
    AuthQuery,
}

/// The raw `credentials:` block.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialsConfig {
    #[serde(default)]
    pub source: SourceKind,
    #[serde(default)]
    pub file: Option<PathBuf>,
    #[serde(default)]
    pub default_iterations: Option<u32>,
    #[serde(default)]
    pub cluster_nonce_file: Option<PathBuf>,
    #[serde(default)]
    pub auth_query: Option<AuthQueryFileConfig>,
}

/// The raw `credentials.auth_query:` block.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthQueryFileConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub password_env: Option<String>,
    #[serde(default = "default_database")]
    pub database: String,
    pub query: String,
    #[serde(default = "default_cache_ttl_ms")]
    pub cache_ttl_ms: u64,
    #[serde(default)]
    pub negative_cache_ttl_ms: Option<u64>,
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    /// When true, a lookup outage at startup does not prevent the proxy from
    /// serving; the source is consulted on the first login instead.
    #[serde(default)]
    pub lazy: bool,
}

impl CredentialsConfig {
    /// Parse the `credentials:` block from a full config document.
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        let document: WirechaosConfig = serde_yaml::from_str(text)
            .map_err(|_| ConfigError::single("config", "invalid YAML configuration"))?;
        Ok(document.credentials)
    }

    /// Build the credential store this configuration describes.
    pub async fn build_store(&self) -> Result<CredentialStore, ConfigError> {
        match self.source {
            SourceKind::File => {
                let path = self.file.clone().ok_or_else(|| {
                    ConfigError::single("credentials.file", "is required when source is `file`")
                })?;
                CredentialStore::from_file(path)
            }
            SourceKind::AuthQuery => {
                let file = self.auth_query.as_ref().ok_or_else(|| {
                    ConfigError::single(
                        "credentials.auth_query",
                        "is required when source is `auth_query`",
                    )
                })?;

                // Validate the query and resolve `password_env` even when the
                // SQL driver is not compiled in, so a bad config is still a
                // config error rather than a feature error.
                let config = file.resolve()?;
                let lazy = file.lazy;

                #[cfg(feature = "auth-query")]
                {
                    let source = AuthQuerySource::new(config);

                    if !lazy {
                        source.preflight().await.map_err(|_| {
                            ConfigError::single(
                                "credentials.auth_query",
                                "lookup database is not reachable",
                            )
                        })?;
                    }

                    Ok(CredentialStore::from_source(
                        Source::AuthQuery(Box::new(source)),
                        Snapshot::empty(0),
                    ))
                }

                #[cfg(not(feature = "auth-query"))]
                {
                    let _ = (config, lazy);
                    Err(ConfigError::single(
                        "credentials.auth_query",
                        "this build has no `auth-query` feature; rebuild with it enabled",
                    ))
                }
            }
        }
    }

    /// A digest of the configuration *structure* for `/version`.
    ///
    /// It hashes which keys are set and how many lookups are configured, never
    /// the values, so it can detect a config change without disclosing a secret.
    pub fn config_digest(&self) -> String {
        let mut hasher = Sha256::new();

        match self.source {
            SourceKind::File => hasher.update(b"source=file;"),
            SourceKind::AuthQuery => hasher.update(b"source=auth_query;"),
        }

        hasher.update(format!("file={};", self.file.is_some()).as_bytes());
        hasher.update(format!("nonce_file={};", self.cluster_nonce_file.is_some()).as_bytes());
        hasher.update(format!("auth_query_configured={};", self.auth_query.is_some()).as_bytes());

        B64.encode(hasher.finalize())
    }
}

impl AuthQueryFileConfig {
    /// Resolve env-var indirection and validate the query.
    pub fn resolve(&self) -> Result<AuthQueryConfig, ConfigError> {
        AuthQueryConfig::validate(&self.query)
            .map_err(|reason| ConfigError::single("credentials.auth_query.query", reason))?;

        let password = match (&self.password, &self.password_env) {
            (Some(password), _) => Zeroizing::new(password.clone()),
            (None, Some(variable)) => {
                let value = std::env::var(variable).map_err(|_| {
                    ConfigError::single(
                        "credentials.auth_query.password_env",
                        "environment variable is not set",
                    )
                })?;
                Zeroizing::new(value)
            }
            (None, None) => Zeroizing::new(String::new()),
        };

        let cache_ttl = Duration::from_millis(self.cache_ttl_ms);
        let negative_ttl = self
            .negative_cache_ttl_ms
            .map(Duration::from_millis)
            .unwrap_or(NEGATIVE_CACHE_TTL);

        Ok(AuthQueryConfig {
            host: self.host.clone(),
            port: self.port,
            user: self.user.clone(),
            password,
            database: self.database.clone(),
            query: self.query.clone(),
            cache_ttl: if cache_ttl.is_zero() {
                DEFAULT_CACHE_TTL
            } else {
                cache_ttl
            },
            negative_ttl,
            max_entries: self.max_entries,
        })
    }
}

/// Redacting `Debug`: the inline `password`, if used, must not be printed.
impl std::fmt::Debug for AuthQueryFileConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthQueryFileConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("password_env", &self.password_env)
            .field("database", &self.database)
            .field("query", &self.query)
            .field("cache_ttl_ms", &self.cache_ttl_ms)
            .field("negative_cache_ttl_ms", &self.negative_cache_ttl_ms)
            .field("max_entries", &self.max_entries)
            .field("lazy", &self.lazy)
            .finish()
    }
}

/// The subset of `wirechaos.yaml` this task understands.
///
/// Unknown top-level keys are ignored so the rest of the configuration can
/// arrive in later tasks without breaking this loader.
#[derive(Debug, Default, Deserialize)]
pub struct WirechaosConfig {
    #[serde(default)]
    pub credentials: CredentialsConfig,
}

fn default_host() -> String {
    "127.0.0.1".to_owned()
}

fn default_port() -> u16 {
    5432
}

fn default_database() -> String {
    "postgres".to_owned()
}

fn default_cache_ttl_ms() -> u64 {
    DEFAULT_CACHE_TTL.as_millis() as u64
}

fn default_max_entries() -> usize {
    DEFAULT_MAX_ENTRIES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_debug_redacts_an_inline_password() {
        let yaml = "\
credentials:
  source: auth_query
  auth_query:
    user: lookup
    password: \"hunter2\"
    query: \"SELECT usename, passwd FROM lookup($1)\"
";
        let config = CredentialsConfig::from_yaml(yaml).expect("valid config");
        let rendered = format!("{config:?}");

        assert!(!rendered.contains("hunter2"), "password leaked: {rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }
}
