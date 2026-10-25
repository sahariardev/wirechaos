use std::{net::SocketAddr, path::PathBuf, time::Duration};

use serde::Deserialize;

use crate::proxy::auth::credentials::{ConfigError, CredentialStore, CredentialsConfig};
use crate::proxy::conn_registry::DEFAULT_MAX_CONNECTIONS;

/// The startup-relevant subset of `wirechaos.yaml` (design §10).
///
/// Deliberately **no** top-level `deny_unknown_fields`: later tasks add
/// `backend`, `chaos`, `control`, and `observability` blocks, and an older build
/// must keep starting when it sees them.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub listen: ListenConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub credentials: CredentialsConfig,
    #[serde(default)]
    pub backend: BackendConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    /// `host:port` of the PostgreSQL backend.
    #[serde(default = "default_backend_address")]
    pub address: String,

    #[serde(default = "default_backend_connect_timeout_ms")]
    pub connect_timeout_ms: u64,

    /// Deadline for the backend startup handshake, including authentication.
    #[serde(default = "default_backend_startup_timeout_ms")]
    pub startup_timeout_ms: u64,

    #[serde(default)]
    pub tls: BackendTlsConfig,

    /// Legacy spelling of `tls.domain`. Kept so existing configuration files
    /// keep working; the value is used only when `tls.domain` is unset.
    #[serde(default)]
    pub tls_domain: Option<String>,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            address: default_backend_address(),
            connect_timeout_ms: default_backend_connect_timeout_ms(),
            startup_timeout_ms: default_backend_startup_timeout_ms(),
            tls: BackendTlsConfig::default(),
            tls_domain: None,
        }
    }
}

/// libpq-compatible `sslmode` policy for the proxy→backend link (design §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendTlsMode {
    /// No `SSLRequest`; the link is plaintext.
    Disable,
    /// Try TLS, fall back to plaintext on `'N'`, never validate the certificate.
    #[default]
    Prefer,
    /// Require TLS and validate the chain, but not the host name.
    Require,
    /// Require TLS and validate both the chain and the host name.
    VerifyFull,
}

/// Client-role SCRAM channel-binding policy (design §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChannelBindingMode {
    /// Always use `SCRAM-SHA-256` with the `n` GS2 flag.
    Disable,
    /// Use `-PLUS` when TLS and a defined certificate hash are available.
    #[default]
    Prefer,
    /// Require `-PLUS`; fail when the backend cannot be bound.
    Require,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct BackendTlsConfig {
    #[serde(default)]
    pub mode: BackendTlsMode,

    /// PEM bundle used to validate the backend certificate. When unset, the
    /// public WebPKI roots are used.
    #[serde(default)]
    pub root_cert_file: Option<PathBuf>,

    #[serde(default)]
    pub channel_binding: ChannelBindingMode,

    /// The host name used for SNI and `verify-full` name checking. Defaults to
    /// the host part of `backend.address`.
    #[serde(default)]
    pub domain: Option<String>,
}

impl BackendConfig {
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }

    pub fn startup_timeout(&self) -> Duration {
        Duration::from_millis(self.startup_timeout_ms)
    }

    /// The name to use for SNI and certificate validation.
    pub fn tls_server_name(&self, host: &str) -> Option<String> {
        self.tls
            .domain
            .clone()
            .or_else(|| self.tls_domain.clone())
            .or_else(|| Some(host.to_owned()))
    }
}

fn default_backend_address() -> String {
    "127.0.0.1:5432".to_owned()
}

fn default_backend_connect_timeout_ms() -> u64 {
    2_000
}

fn default_backend_startup_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

    pub fn backend_host_port(&self) -> Result<(String, u16), ConfigError> {
        let (host, port) = self.backend.address.rsplit_once(':').ok_or_else(|| {
            ConfigError::single("backend.address", "must be a host:port socket address")
        })?;

        if host.is_empty() {
            return Err(ConfigError::single(
                "backend.address",
                "must be a host:port socket address",
            ));
        }

        let port = port.parse::<u16>().map_err(|_| {
            ConfigError::single("backend.address", "must be a host:port socket address")
        })?;

        Ok((host.to_owned(), port))
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

    #[test]
    fn backend_tls_and_timeouts_match_the_documented_keys() {
        let config = Config::from_yaml(
            "backend:\n  address: \"db.internal:5432\"\n  connect_timeout_ms: 1500\n  startup_timeout_ms: 7000\n  tls:\n    mode: verify-full\n    root_cert_file: /etc/ssl/certs/ca.pem\n    channel_binding: require\n    domain: db.internal\n",
        )
        .expect("valid backend block");

        assert_eq!(
            config.backend.connect_timeout(),
            Duration::from_millis(1_500)
        );
        assert_eq!(
            config.backend.startup_timeout(),
            Duration::from_millis(7_000)
        );
        assert_eq!(config.backend.tls.mode, BackendTlsMode::VerifyFull);
        assert_eq!(
            config.backend.tls.channel_binding,
            ChannelBindingMode::Require
        );
        assert_eq!(
            config.backend.tls_server_name("127.0.0.1").as_deref(),
            Some("db.internal")
        );
        assert_eq!(
            config.backend_host_port().expect("address"),
            ("db.internal".to_owned(), 5432)
        );
    }

    #[test]
    fn backend_defaults_are_libpq_compatible() {
        let config = Config::from_yaml("{}").expect("empty config");

        assert_eq!(config.backend.tls.mode, BackendTlsMode::Prefer);
        assert_eq!(
            config.backend.tls.channel_binding,
            ChannelBindingMode::Prefer
        );
        assert_eq!(config.backend.startup_timeout().as_millis(), 5_000);
    }
}
