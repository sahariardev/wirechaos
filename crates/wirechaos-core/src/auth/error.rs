
#[derive(Debug)]
pub enum ScramError {
    AuthenticationFailed,
    Protocol(String),
}

impl std::fmt::Display for ScramError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ScramError::AuthenticationFailed => write!(f, "Authentication failed"),
            ScramError::Protocol(error) => write!(f, "scram protocol violation{}", error),
        }
    }
}