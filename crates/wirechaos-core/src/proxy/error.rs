use crate::proxy::InternalError;
use std::fmt::{self, write};

pub trait ClientAwareError: fmt::Debug {
    fn code(&self) -> &str;
    fn message(&self) -> &str;
}

#[derive(Debug)]
pub enum ProxyError {
    Internal(InternalError),
    ConnectionError(Box<dyn ClientAwareError>),
}

impl std::io::Error for ProxyError {}

impl ProxyError {
    pub fn internal(error: impl Into<InternalError>) -> Self {
        Self::Internal(error.into())
    }
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Internal(error) => write!(f, "{error}"),
            Self::ConnectionError(error) => write!(f, "{}", error.message()),
        }
    }
}

pub fn connection_error(error: ConnectionErrorInner) -> ProxyError {
    ProxyError::ConnectionError(Box::new(error))
}

#[derive(Debug)]
pub enum ConnectionErrorInner {
    TooManyRequest,
    FirstMessageTooBig,
    AuthTimeout,
    EmptyMessageBody,
    InvalidMessageLength,
    TlsRequired,
    TlsAlreadyDone,
    InvalidData,
    GssAlreadyDone,
    AuthFailed,
    InvalidState,
}

impl std::io::Error for ConnectionErrorInner {}

impl fmt::Display for ConnectionErrorInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyRequest => write!(f, "sorry, too many clients already."),
            Self::FirstMessageTooBig => write!(f, "invalid startup packet."),
            Self::AuthTimeout => write!(f, "cancelling authentication due to timeout."),
            Self::EmptyMessageBody => write!(f, "empty message body."),
            Self::InvalidMessageLength => write!(f, "invalid message length."),
            Self::TlsRequired => write!(f, "TLS required. But client did not send it"),
            Self::TlsAlreadyDone => write!(f, "Tls already done."),
            Self::InvalidData => write!(f, "invalid data."),
            Self::GssAlreadyDone => write!(f, "GSS already done."),
            Self::AuthFailed => write!(f, "authentication rejected."),
            Self::InvalidState => write!(f, "invalid state."),
        }
    }
}

impl ClientAwareError for ConnectionErrorInner {
    fn code(&self) -> &str {
        match self {
            Self::TooManyRequest => "53300",
            Self::FirstMessageTooBig => "08P01",
            Self::AuthTimeout => "57014",
            Self::EmptyMessageBody => "08P01",
            Self::InvalidMessageLength => "08P01",
            Self::TlsRequired => "08P01",
            Self::TlsAlreadyDone => "08P01",
            Self::InvalidData => "08P01",
            Self::GssAlreadyDone => "08P01",
            Self::AuthFailed => "08P01",
            Self::InvalidState => "08P01",
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::TooManyRequest => "sorry, too many clients already.",
            Self::FirstMessageTooBig => "invalid startup packet.",
            Self::AuthTimeout => "cancelling authentication due to timeout.",
            Self::EmptyMessageBody => "empty message body.",
            Self::InvalidMessageLength => "invalid message length.",
            Self::TlsRequired => "TLS required. But client did not send it",
            Self::TlsAlreadyDone => "Tls already done.",
            Self::InvalidData => "invalid data.",
            Self::GssAlreadyDone => "GSS already done.",
            Self::AuthFailed => "authentication rejected.",
            Self::InvalidState => "invalid state.",
        }
    }
}
