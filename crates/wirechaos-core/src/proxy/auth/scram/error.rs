use crate::proxy::auth::error::AuthError;
use std::error::Error;

#[derive(Debug)]
pub enum ScramError {
    AuthenticationFailed(String),
    Protocol(String),
    /// The client's `c=` did not match the binding this server computed for its
    /// certificate. Reported as `28P01`, like any other authentication failure.
    ChannelBindingMismatch,
    /// The client claimed (`y`) that it supports channel binding but believes
    /// the server does not, after the server advertised `-PLUS`. Reported as
    /// `08P01`: accepting it would be a negotiated downgrade.
    ChannelBindingDowngrade,
}

impl Error for ScramError {}

impl AuthError for ScramError {
    fn code(&self) -> &str {
        match self {
            ScramError::AuthenticationFailed(_) | ScramError::ChannelBindingMismatch => "28P01",
            ScramError::Protocol(_) | ScramError::ChannelBindingDowngrade => "08P01",
        }
    }

    fn message(&self) -> &str {
        match self {
            ScramError::AuthenticationFailed(msg) => msg,
            ScramError::Protocol(msg) => msg,
            ScramError::ChannelBindingMismatch => "SCRAM channel binding check failed",
            ScramError::ChannelBindingDowngrade => {
                "client supports SCRAM channel binding but thinks the server does not. \
                 However, this server does support channel binding."
            }
        }
    }
}

impl std::fmt::Display for ScramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScramError::AuthenticationFailed(message) => write!(f, "{message}"),
            ScramError::Protocol(error) => {
                write!(f, "scram_authenticator protocol violation: {error}")
            }
            ScramError::ChannelBindingMismatch | ScramError::ChannelBindingDowngrade => {
                write!(f, "{}", self.message())
            }
        }
    }
}
