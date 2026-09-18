use crate::proxy::ProxyError;
use std::fmt;

pub trait AuthError: std::error::Error + Send + Sync {
    fn code(&self) -> &str;
    fn message(&self) -> &str;
}


pub enum AuthFailure {
    Rejected(Box<dyn AuthError>),
    Internal(ProxyError),
}

impl AuthFailure {
    pub fn rejected(error: impl AuthError + 'static) -> Self {
        Self::Rejected(Box::new(error))
    }

    pub fn internal(error: impl Into<ProxyError>) -> Self {
        Self::Internal(error.into())
    }
}

impl fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(error) => write!(f, "{error}"),
            Self::Internal(error) => write!(f, "{error}"),
        }
    }
}

impl fmt::Debug for AuthFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(error) => write!(f, "Rejected({error})"),
            Self::Internal(error) => write!(f, "Internal({error})"),
        }
    }
}

impl std::error::Error for AuthFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rejected(error) => Some(error.as_ref() as &(dyn std::error::Error + 'static)),
            Self::Internal(error) => Some(error.as_ref()),
        }
    }
}
