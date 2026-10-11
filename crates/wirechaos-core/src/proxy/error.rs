use crate::proxy::InternalError;
use std::error::Error;
use std::fmt::{self};

pub trait ClientAwareError: fmt::Debug + Error + Send + Sync + 'static {
    fn code(&self) -> &str;
    fn message(&self) -> &str;
}

#[derive(Debug)]
pub enum ProxyError {
    Internal(InternalError),
    ConnectionError(Box<dyn ClientAwareError>),
}

impl Error for ProxyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ProxyError::Internal(err) => Some(err.as_ref()),
            ProxyError::ConnectionError(err) => Some(err.as_ref()),
        }
    }
}

impl ProxyError {
    pub fn internal(error: impl Into<InternalError>) -> Self {
        Self::Internal(error.into())
    }
}

impl From<InternalError> for ProxyError {
    fn from(err: InternalError) -> Self {
        ProxyError::Internal(err)
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

impl Error for ConnectionErrorInner {}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_err_is_a_standard_error() {
        let err = connection_error(ConnectionErrorInner::TooManyRequest);
        let _: &dyn std::error::Error = &err;
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ProxyError>();
        assert!(err.source().is_none());
    }

    #[test]
    fn internal_error_converts_via_question_mark() {
        fn fallible() -> Result<(), ProxyError> {
            let internal: InternalError = "to blew up".into();
            Err(internal)?;
            Ok(())
        }

        assert!(fallible().is_err())
    }
}
