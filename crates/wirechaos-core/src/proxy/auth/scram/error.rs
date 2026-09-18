use std::error::Error;
use crate::proxy::auth::error::AuthError;

#[derive(Debug)]
pub enum ScramError {
    AuthenticationFailed,
    Protocol(String),
}

impl Error for ScramError {}

impl AuthError for ScramError {
    fn code(&self) -> &str {
        match self {
            ScramError::AuthenticationFailed => "28P01",
            ScramError::Protocol(_) => "08P01",
        }
    }

    fn message(&self) -> &str {
        match self {
            ScramError::AuthenticationFailed => "Authentication failed",
            ScramError::Protocol(msg) => msg,
        }
    }
}

impl std::fmt::Display for ScramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScramError::AuthenticationFailed => write!(f, "Authentication failed"),
            ScramError::Protocol(error) => {
                write!(f, "scram_authenticator protocol violation: {error}")
            }
        }
    }
}
