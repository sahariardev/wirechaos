mod error;
mod pg_client;
pub mod registry;
mod scram_client;
pub mod session_key_secret;
mod timeout_stream;

pub use crate::proxy::backend::error::{classify_backend_error, BackendErrorClass, PgError};
use crate::proxy::backend::pg_client::PgClient;
pub use crate::proxy::backend::pg_client::PgConfig;
use crate::proxy::buffer_pool::MultiBufferPool;
use crate::proxy::conn::CANCEL_REQUEST_CODE;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// The backend's real cancel key, captured from `BackendKeyData`.
///
/// It is never sent to the client: the proxy mints its own pair and keeps this
/// one in the session registry so a `CancelRequest` can be routed (task 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendKeyData {
    pub pid: i32,
    pub secret: i32,
}

/// A startup-phase message that must be replayed to the client, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupNotification {
    ParameterStatus(String, String),
    Notice(Vec<u8>),
}

pub struct Backend {
    startup_notifications: Vec<StartupNotification>,
    backend_key: Option<BackendKeyData>,
    ready_status: u8,
    server_signature_verified: bool,
    host: String,
    port: u16,
    connect_timeout: Duration,
    // Kept alive for the lifetime of the backend link: the TCP/TLS stream and
    // the SCRAM state machine are not usable after the client is dropped.
    #[allow(
        dead_code,
        reason = "held for the session lifetime; dropping it closes the backend connection"
    )]
    client: PgClient,
    #[allow(
        dead_code,
        reason = "held alongside the client so the pool outlives every rented buffer"
    )]
    pool: Arc<MultiBufferPool>,
}

impl Backend {
    pub fn get_param_status_values(&self) -> Vec<(String, String)> {
        self.startup_notifications
            .iter()
            .filter_map(|notification| match notification {
                StartupNotification::ParameterStatus(name, value) => {
                    Some((name.clone(), value.clone()))
                }
                StartupNotification::Notice(_) => None,
            })
            .collect()
    }

    /// The startup-phase messages to replay to the client, in backend order.
    pub fn startup_notifications(&self) -> &[StartupNotification] {
        &self.startup_notifications
    }

    #[must_use]
    pub fn backend_key(&self) -> Option<BackendKeyData> {
        self.backend_key
    }

    #[must_use]
    pub fn ready_status(&self) -> u8 {
        self.ready_status
    }

    /// True when the backend's `v=` signature was checked with `ServerKey`,
    /// false when no `ServerKey` was available (the session logs a warning).
    #[must_use]
    pub fn server_signature_verified(&self) -> bool {
        self.server_signature_verified
    }

    /// Forward a `CancelRequest` on a fresh, short-lived connection.
    ///
    /// PostgreSQL cancel connections are unauthenticated and carry no TLS, even
    /// when the session itself is encrypted. Nothing is written to the client's
    /// cancel connection; the caller closes it after this returns.
    pub async fn send_cancel_request(&self, key: BackendKeyData) -> Result<(), PgError> {
        let mut stream = tokio::time::timeout(
            self.connect_timeout,
            TcpStream::connect((self.host.as_str(), self.port)),
        )
        .await
        .map_err(|_| PgError::ConnectTimeout)??;

        let mut packet = Vec::with_capacity(16);
        packet.extend_from_slice(&16u32.to_be_bytes());
        packet.extend_from_slice(&CANCEL_REQUEST_CODE.to_be_bytes());
        packet.extend_from_slice(&(key.pid as u32).to_be_bytes());
        packet.extend_from_slice(&(key.secret as u32).to_be_bytes());

        stream.write_all(&packet).await?;
        stream.flush().await?;
        stream.shutdown().await?;

        Ok(())
    }

    pub async fn new(config: PgConfig, pool: Arc<MultiBufferPool>) -> Result<Arc<Self>, PgError> {
        let mut client = PgClient::connect(config, Arc::clone(&pool)).await?;

        let backend = Self {
            startup_notifications: client.take_startup_notifications(),
            backend_key: client.backend_key(),
            ready_status: client.ready_status().unwrap_or(b'I'),
            server_signature_verified: client.server_signature_verified(),
            host: client.host().to_owned(),
            port: client.port(),
            connect_timeout: client.connect_timeout(),
            client,
            pool,
        };

        Ok(Arc::new(backend))
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            client: PgClient::for_test(),
            pool: MultiBufferPool::new(16, 16, 0),
            startup_notifications: Vec::new(),
            backend_key: None,
            ready_status: b'I',
            server_signature_verified: false,
            host: String::new(),
            port: 0,
            connect_timeout: Duration::from_secs(1),
        }
    }
}

/// PostgreSQL's MD5 password response:
/// `"md5" ‖ hex(md5(hex(md5(password ‖ user)) ‖ salt))`.
#[must_use]
pub fn md5_response(user: &str, password: &[u8], salt: &[u8; 4]) -> String {
    let inner = format!("{:x}", md5::compute([password, user.as_bytes()].concat()));
    let outer = md5::compute([inner.as_bytes(), salt.as_slice()].concat());

    format!("md5{outer:x}")
}

/// One entry of the backend's `SASL` mechanism list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslMechanism {
    ScramSha256,
    ScramSha256Plus,
}

impl SaslMechanism {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::ScramSha256Plus => "SCRAM-SHA-256-PLUS",
        }
    }
}

/// Parse the NUL-separated mechanism list of `AuthenticationSASL`.
#[must_use]
pub fn parse_sasl_mechanisms(body: &[u8]) -> Vec<SaslMechanism> {
    body.split(|&byte| byte == 0)
        .filter_map(|name| match name {
            b"SCRAM-SHA-256" => Some(SaslMechanism::ScramSha256),
            b"SCRAM-SHA-256-PLUS" => Some(SaslMechanism::ScramSha256Plus),
            _ => None,
        })
        .collect()
}

/// How the backend answered the `SSLRequest` dance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslReply {
    NotRequested,
    No,
    Yes,
}

/// The TLS policy decision from the table in design §3.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsOutcome {
    Plaintext,
    Tls { verify_host: bool },
    Fail,
}

/// Apply `backend.tls.mode` to the backend's `SSLRequest` reply.
#[must_use]
pub fn decide_tls(mode: crate::proxy::config::BackendTlsMode, reply: SslReply) -> TlsOutcome {
    use crate::proxy::config::BackendTlsMode::{Disable, Prefer, Require, VerifyFull};
    use SslReply::{No, NotRequested, Yes};
    use TlsOutcome::{Fail, Plaintext, Tls};

    match (mode, reply) {
        (Disable, NotRequested) => Plaintext,
        (Prefer, NotRequested | No) => Plaintext,
        (Prefer | Require, Yes) => Tls { verify_host: false },
        (VerifyFull, Yes) => Tls { verify_host: true },
        (Require | VerifyFull, No | NotRequested) => Fail,
        (Disable, No | Yes) => Fail,
    }
}

/// The mechanism a client-role SCRAM exchange must select (design §5.2).
pub fn select_mechanism(
    mode: crate::proxy::config::ChannelBindingMode,
    channel_binding_available: bool,
    offered: &[SaslMechanism],
) -> Result<SaslMechanism, PgError> {
    use crate::proxy::config::ChannelBindingMode;

    let plus_offered = offered.contains(&SaslMechanism::ScramSha256Plus);
    let plain_offered = offered.contains(&SaslMechanism::ScramSha256);

    match mode {
        ChannelBindingMode::Disable => {
            if plain_offered {
                Ok(SaslMechanism::ScramSha256)
            } else {
                Err(PgError::UnsupportedAuth(
                    "backend requires channel binding, but channel_binding is disabled".into(),
                ))
            }
        }
        ChannelBindingMode::Prefer => {
            if plus_offered && channel_binding_available {
                Ok(SaslMechanism::ScramSha256Plus)
            } else if plain_offered {
                Ok(SaslMechanism::ScramSha256)
            } else {
                Err(PgError::UnsupportedAuth(
                    "backend offered no SCRAM-SHA-256 mechanism the proxy can use".into(),
                ))
            }
        }
        ChannelBindingMode::Require => {
            if !channel_binding_available {
                return Err(PgError::ChannelBindingRequired(
                    "the backend connection is not TLS or its certificate has no defined tls-server-end-point hash".into(),
                ));
            }

            if plus_offered {
                Ok(SaslMechanism::ScramSha256Plus)
            } else {
                Err(PgError::ChannelBindingRequired(
                    "the backend does not offer SCRAM-SHA-256-PLUS".into(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::config::ChannelBindingMode;

    #[test]
    fn md5_response_is_computed_like_postgresql() {
        let user = "alice";
        let password = b"alice-pw";
        let salt = [0x01u8, 0x02, 0x03, 0x04];

        let inner = format!("{:x}", md5::compute(format!("{}{}", "alice-pw", user)));
        let expected = format!("md5{:x}", md5::compute([inner.as_bytes(), &salt].concat()));

        assert_eq!(md5_response(user, password, &salt), expected);
    }

    #[test]
    fn channel_binding_modes_choose_the_right_mechanism() {
        let mechanisms = vec![SaslMechanism::ScramSha256Plus, SaslMechanism::ScramSha256];

        assert_eq!(
            select_mechanism(ChannelBindingMode::Disable, true, &mechanisms).unwrap(),
            SaslMechanism::ScramSha256
        );
        assert_eq!(
            select_mechanism(ChannelBindingMode::Prefer, true, &mechanisms).unwrap(),
            SaslMechanism::ScramSha256Plus
        );
        assert_eq!(
            select_mechanism(ChannelBindingMode::Prefer, false, &mechanisms).unwrap(),
            SaslMechanism::ScramSha256
        );
        assert_eq!(
            select_mechanism(
                ChannelBindingMode::Require,
                true,
                &[SaslMechanism::ScramSha256Plus]
            )
            .unwrap(),
            SaslMechanism::ScramSha256Plus
        );

        assert!(select_mechanism(ChannelBindingMode::Require, false, &mechanisms).is_err());
        assert!(select_mechanism(
            ChannelBindingMode::Require,
            true,
            &[SaslMechanism::ScramSha256]
        )
        .is_err());
    }

    #[test]
    fn tls_mode_decision_table() {
        use crate::proxy::config::BackendTlsMode::{Disable, Prefer, Require, VerifyFull};
        use SslReply::{No, NotRequested, Yes};
        use TlsOutcome::{Fail, Plaintext, Tls};

        let cases = [
            (Disable, NotRequested, Plaintext),
            (Prefer, No, Plaintext),
            (Prefer, Yes, Tls { verify_host: false }),
            (Require, No, Fail),
            (Require, Yes, Tls { verify_host: false }),
            (VerifyFull, No, Fail),
            (VerifyFull, Yes, Tls { verify_host: true }),
        ];

        for (mode, reply, expected) in cases {
            assert_eq!(decide_tls(mode, reply), expected, "{mode:?} / {reply:?}");
        }
    }

    #[test]
    fn sasl_mechanism_lists_are_parsed_until_the_terminator() {
        let body = b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0";
        assert_eq!(
            parse_sasl_mechanisms(body),
            vec![SaslMechanism::ScramSha256Plus, SaslMechanism::ScramSha256]
        );
    }

    #[test]
    fn param_status_values_keep_backend_order() {
        let backend = Backend {
            startup_notifications: vec![
                StartupNotification::ParameterStatus("server_version".into(), "17.2".into()),
                StartupNotification::Notice(b"notice".to_vec()),
                StartupNotification::ParameterStatus("client_encoding".into(), "UTF8".into()),
            ],
            backend_key: None,
            ready_status: b'I',
            server_signature_verified: false,
            host: String::new(),
            port: 0,
            connect_timeout: Duration::from_secs(1),
            client: PgClient::for_test(),
            pool: MultiBufferPool::new(16, 16, 0),
        };

        assert_eq!(
            backend.get_param_status_values(),
            vec![
                ("server_version".to_owned(), "17.2".to_owned()),
                ("client_encoding".to_owned(), "UTF8".to_owned()),
            ]
        );
    }
}
