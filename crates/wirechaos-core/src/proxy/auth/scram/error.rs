use crate::proxy::auth::error::AuthError;
use std::error::Error;

#[derive(Debug)]
pub enum ScramError {
    AuthenticationFailed(String),
    Protocol(String),
}

impl Error for ScramError {}

impl AuthError for ScramError {
    fn code(&self) -> &str {
        match self {
            ScramError::AuthenticationFailed(_) => "28P01",
            ScramError::Protocol(_) => "08P01",
        }
    }

    fn message(&self) -> &str {
        match self {
            ScramError::AuthenticationFailed(msg) => msg,
            ScramError::Protocol(msg) => msg,
        }
    }
}

impl std::fmt::Display for ScramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScramError::AuthenticationFailed(message) => {
                write!(f, "{message}")
            }
            ScramError::Protocol(error) => {
                write!(f, "scram_authenticator protocol violation: {error}")
            }
        }
    }
}
