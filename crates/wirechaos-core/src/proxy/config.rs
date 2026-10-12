use std::{net::SocketAddr, time::Duration};

use serde::Deserialize;

use crate::proxy::auth::credentials::{ConfigError, CredentialStore, CredentialsConfig};
use crate::proxy::conn_registry::DEFAULT_MAX_CONNECTIONS;

/// The startup-relevant subset of `wirechaos.yaml` (design §10).
///
/// Deliberately **no** top-level `deny_unknown_fields`: later tasks add
/// `backend`, `chaos`, `control`, and `observability` blocks, and an older build
/// must keep starting when it sees them.
#[derive(Debug, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub listen: ListenConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub credentials: CredentialsConfig,
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    /// `host:port` the frontend accepts on.
    #[serde(default = "default_frontend")]
    pub frontend: String,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            frontend: default_frontend(),
        }
    }
}

fn default_frontend() -> String {
    "127.0.0.1:6432".to_owned()
}

#[derive(Debug, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    #[serde(default = "default_authentication_timeout_ms")]
    pub authentication_timeout_ms: u64,

    #[serde(default = "default_max_startup_bytes")]
    pub max_startup_bytes: usize,

    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,

    #[serde(default)]
    pub idle_timeout_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            authentication_timeout_ms: default_authentication_timeout_ms(),
            max_startup_bytes: default_max_startup_bytes(),
            max_message_size: default_max_message_size(),
            idle_timeout_ms: 0,
        }
    }
}

fn default_max_connections() -> u32 {
    DEFAULT_MAX_CONNECTIONS
}

fn default_authentication_timeout_ms() -> u64 {
    60_000
}

fn default_max_startup_bytes() -> usize {
    10_000
}

fn default_max_message_size() -> usize {
    1 << 30
}

impl Config {
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        serde_yaml::from_str(text)
            .map_err(|_| ConfigError::single("config", "invalid YAML configuration"))
    }

    pub fn frontend_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.listen.frontend.parse().map_err(|_| {
            ConfigError::single("listen.frontend", "must be a host:port socket address")
        })
    }

    pub fn authentication_timeout(&self) -> Duration {
        Duration::from_millis(self.limits.authentication_timeout_ms)
    }

    pub fn max_startup_bytes(&self) -> usize {
        self.limits.max_startup_bytes
    }

    pub async fn build_credential_store(&self) -> Result<CredentialStore, ConfigError> {
        self.credentials.build_store().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_documented_limits() {
        let config = Config::from_yaml("{}").expect("an empty document is valid");

        assert_eq!(config.limits.max_connections, 100);
        assert_eq!(config.limits.authentication_timeout_ms, 60_000);
        assert_eq!(config.limits.max_startup_bytes, 10_000);
        assert_eq!(config.frontend_addr().expect("default addr").port(), 6432);
    }

    #[test]
    fn future_top_level_blocks_do_not_break_startup() {
        // Later tasks add `backend`, `chaos`, `control`, `observability`; an
        // older binary must ignore them rather than refuse to boot.
        let config = Config::from_yaml(
            "backend:\n  address: \"127.0.0.1:5432\"\nlimits:\n  max_connections: 7\n",
        )
        .expect("unknown blocks are ignored");

        assert_eq!(config.limits.max_connections, 7);
    }

    #[test]
    fn a_bad_frontend_address_is_a_config_error_not_a_panic() {
        let config = Config::from_yaml("listen:\n  frontend: \"not-an-addr\"\n").unwrap();
        assert!(config.frontend_addr().is_err());
    }

    #[test]
    fn authentication_timeout_is_milliseconds() {
        let config = Config::from_yaml("limits:\n  authentication_timeout_ms: 250\n").unwrap();
        assert_eq!(config.authentication_timeout(), Duration::from_millis(250));
    }
}
