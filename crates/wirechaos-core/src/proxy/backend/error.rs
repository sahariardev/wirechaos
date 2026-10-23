#[derive(Debug, thiserror::Error)]
pub enum PgError {
    #[error("operation timed out")]
    Timeout,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(String),
}
