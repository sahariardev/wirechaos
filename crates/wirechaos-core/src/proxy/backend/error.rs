use crate::proxy::error::{ClientAwareError, ProxyError};

#[derive(Debug, thiserror::Error)]
pub enum PgError {
    #[error("operation timed out")]
    Timeout,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("auth error: {0}")]
    Auth(String),
}

impl ClientAwareError for PgError {
    fn code(&self) -> &str {
        match self {
            Self::Auth(_) => "28P01",
            Self::Protocol(_) => "08P01",
            Self::Timeout | Self::Io(_) => "08006",
        }
    }

    fn message(&self) -> &str {
        // The client gets a stable, generic failure. The detail stays in the
        // backend error (and therefore in the session log), never on the wire.
        match self {
            Self::Auth(_) => "backend authentication failed",
            Self::Protocol(_) => "backend sent an invalid protocol message",
            Self::Timeout | Self::Io(_) => "could not connect to the backend database",
        }
    }
}

impl From<PgError> for ProxyError {
    fn from(err: PgError) -> Self {
        ProxyError::ConnectionError(Box::new(err))
    }
}
