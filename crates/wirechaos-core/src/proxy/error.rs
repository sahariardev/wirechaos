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
    MessageTooLarge,
    TlsRequired,
    TlsAlreadyDone,
    InvalidData,
    GssAlreadyDone,
    AuthFailed,
    InvalidState,
    StatementCanceled,
    InvalidStartupLayout,
    MissingUser,
}

impl Error for ConnectionErrorInner {}

impl fmt::Display for ConnectionErrorInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl ClientAwareError for ConnectionErrorInner {
    fn code(&self) -> &str {
        match self {
            Self::TooManyRequest => "53300",
            Self::AuthTimeout | Self::StatementCanceled => "57014",
            Self::FirstMessageTooBig
            | Self::EmptyMessageBody
            | Self::InvalidMessageLength
            | Self::MessageTooLarge
            | Self::InvalidStartupLayout => "08P01",
            Self::MissingUser => "28000",
            Self::AuthFailed => "28P01",
            Self::TlsRequired
            | Self::TlsAlreadyDone
            | Self::GssAlreadyDone
            | Self::InvalidData
            | Self::InvalidState => "08P01",
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::TooManyRequest => "sorry, too many clients already",
            Self::AuthTimeout => "canceling authentication due to timeout",
            Self::StatementCanceled => "canceling statement due to user request",
            Self::FirstMessageTooBig | Self::InvalidStartupLayout => {
                "invalid startup packet layout"
            }
            Self::EmptyMessageBody => "empty message body",
            Self::InvalidMessageLength => "invalid message length",
            Self::MessageTooLarge => "message length exceeds the buffer pool capacity",
            Self::MissingUser => "no PostgreSQL user name specified in startup packet",
            Self::AuthFailed => "password authentication failed",
            Self::TlsRequired => "TLS is required but the client did not request it",
            Self::TlsAlreadyDone => "SSLRequest was already answered on this connection",
            Self::GssAlreadyDone => "GSSENCRequest was already answered on this connection",
            Self::InvalidData => "invalid data",
            Self::InvalidState => "invalid session state",
        }
    }
}

#[derive(Debug)]
pub struct ProtocolError {
    code: &'static str,
    message: String,
}

impl ProtocolError {
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl Error for ProtocolError {}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl ClientAwareError for ProtocolError {
    fn code(&self) -> &str {
        self.code
    }

    fn message(&self) -> &str {
        &self.message
    }
}

pub fn protocol_error(code: &'static str, message: impl Into<String>) -> ProxyError {
    ProxyError::ConnectionError(Box::new(ProtocolError::new(code, message)))
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
        assert!(err.source().is_some(), "the client error is the source");
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

    #[test]
    fn startup_error_codes_and_wording_match_postgresql() {
        use ConnectionErrorInner::*;

        assert_eq!(TooManyRequest.code(), "53300");
        assert_eq!(TooManyRequest.message(), "sorry, too many clients already");

        assert_eq!(AuthTimeout.code(), "57014");
        assert_eq!(
            AuthTimeout.message(),
            "canceling authentication due to timeout"
        );

        assert_eq!(FirstMessageTooBig.code(), "08P01");
        assert_eq!(
            FirstMessageTooBig.message(),
            "invalid startup packet layout"
        );

        assert_eq!(MissingUser.code(), "28000");
        assert_eq!(
            MissingUser.message(),
            "no PostgreSQL user name specified in startup packet"
        );
    }

    #[test]
    fn runtime_protocol_error_carries_its_code_and_message() {
        let err = protocol_error(
            "0A000",
            "unsupported frontend protocol 4.0: server supports 3.0 to 3.0",
        );

        match &err {
            ProxyError::ConnectionError(inner) => {
                assert_eq!(inner.code(), "0A000");
                assert_eq!(
                    inner.message(),
                    "unsupported frontend protocol 4.0: server supports 3.0 to 3.0"
                );
            }
            ProxyError::Internal(_) => panic!("expected a client-facing error"),
        }
    }
}
