use crate::proxy::error::{ClientAwareError, ProxyError};

/// What the client is allowed to learn about a backend startup failure.
///
/// Errors that describe *the user's* request (a missing database, a full server)
/// are passed through because acting on them is possible. Errors that describe
/// the proxy's own credentials or plumbing are generalised on the wire and kept
/// in the log, where an operator can see them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendErrorClass {
    Generalised,
    PassThrough,
}

#[must_use]
pub fn classify_backend_error(sqlstate: &str) -> BackendErrorClass {
    match sqlstate {
        // The database/role the user asked for does not exist, the server is at
        // its connection limit, or it is still starting up. All actionable.
        "3D000" | "53300" | "57P03" => BackendErrorClass::PassThrough,
        // Credential and transport failures are the proxy's problem, not the
        // client's; leaking their detail would disclose backend topology.
        _ => BackendErrorClass::Generalised,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PgError {
    #[error("backend connect timed out")]
    ConnectTimeout,

    #[error("backend TLS handshake timed out")]
    TlsTimeout,

    #[error("backend did not finish starting up")]
    StartupTimeout,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("backend authentication failed: {0}")]
    Auth(String),

    /// The backend asked for an authentication method the proxy cannot satisfy
    /// with the credential material it holds. The detail is intentionally
    /// client-visible: it names the operator's fix (for example "configure a
    /// plaintext password" or "reprovision the secret with the same salt").
    #[error("{0}")]
    UnsupportedAuth(String),

    /// The frontend exchange and the backend use different salts, so the
    /// captured `ClientKey` cannot produce a proof for the backend.
    #[error("salt mismatch: the backend's SCRAM salt differs from the salt used for the client")]
    SaltMismatch,

    #[error("channel binding required, but {0}")]
    ChannelBindingRequired(String),

    /// A structured `ErrorResponse` returned by the backend during startup.
    #[error("backend error {code} ({severity}): {message}")]
    Backend {
        severity: String,
        code: String,
        message: String,
    },
}

impl PgError {
    fn generalised_message(&self) -> &str {
        match self {
            Self::Auth(_) | Self::SaltMismatch => "backend authentication failed",
            Self::ConnectTimeout | Self::TlsTimeout | Self::Io(_) | Self::Tls(_) => {
                "could not connect to the backend database"
            }
            Self::StartupTimeout => "backend did not finish starting up",
            Self::Protocol(_) => "backend sent an invalid protocol message",
            Self::UnsupportedAuth(message) | Self::ChannelBindingRequired(message) => message,
            Self::Backend { code, .. } if code.starts_with("28") => "backend authentication failed",
            Self::Backend { code, .. } if code.starts_with("08") => {
                "could not connect to the backend database"
            }
            Self::Backend { .. } => "backend failed during startup",
        }
    }
}

impl ClientAwareError for PgError {
    fn code(&self) -> &str {
        match self {
            Self::Auth(_)
            | Self::UnsupportedAuth(_)
            | Self::SaltMismatch
            | Self::ChannelBindingRequired(_) => "28P01",
            Self::Protocol(_) => "08P01",
            Self::Backend { code, .. } => code,
            Self::ConnectTimeout | Self::TlsTimeout | Self::Io(_) | Self::Tls(_) => "08006",
            Self::StartupTimeout => "08006",
        }
    }

    fn message(&self) -> &str {
        // The client gets a stable, generic failure for every proxy-side
        // problem. The detail stays in the error (and therefore in the session
        // log), never on the wire.
        match self {
            Self::Backend { code, message, .. } => {
                if classify_backend_error(code) == BackendErrorClass::PassThrough {
                    message
                } else {
                    self.generalised_message()
                }
            }
            other => other.generalised_message(),
        }
    }
}

impl From<PgError> for ProxyError {
    fn from(err: PgError) -> Self {
        ProxyError::ConnectionError(Box::new(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_errors_are_classified_as_specified() {
        let cases = [
            ("28P01", BackendErrorClass::Generalised),
            ("28000", BackendErrorClass::Generalised),
            ("08006", BackendErrorClass::Generalised),
            ("3D000", BackendErrorClass::PassThrough),
            ("53300", BackendErrorClass::PassThrough),
            ("57P03", BackendErrorClass::PassThrough),
        ];

        for (sqlstate, expected) in cases {
            assert_eq!(classify_backend_error(sqlstate), expected, "{sqlstate}");
        }
    }

    #[test]
    fn pass_through_errors_keep_the_backend_message() {
        let err = PgError::Backend {
            severity: "FATAL".to_owned(),
            code: "3D000".to_owned(),
            message: "database \"appdb\" does not exist".to_owned(),
        };

        assert_eq!(err.code(), "3D000");
        assert_eq!(err.message(), "database \"appdb\" does not exist");
    }

    #[test]
    fn proxy_side_auth_errors_are_generalised_for_the_client() {
        let err = PgError::Backend {
            severity: "FATAL".to_owned(),
            code: "28P01".to_owned(),
            message: "password authentication failed for user \"alice\"".to_owned(),
        };

        assert_eq!(err.code(), "28P01");
        assert_eq!(err.message(), "backend authentication failed");
        assert!(
            err.to_string().contains("password authentication failed"),
            "the log detail must keep the backend's message: {err}"
        );
    }

    #[test]
    fn unsupported_methods_name_the_actionable_cause() {
        let err = PgError::UnsupportedAuth(
            "backend requires MD5 authentication, but only a SCRAM secret is available".to_owned(),
        );

        assert_eq!(err.code(), "28P01");
        assert!(err.message().contains("MD5"));
        assert!(err.message().contains("SCRAM secret"));
    }
}
