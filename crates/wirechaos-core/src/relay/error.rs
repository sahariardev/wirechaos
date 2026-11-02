pub enum RelayError {
    InvalidMessageLength { length: usize },
    MessageTooLong { length: usize, max_length: usize },
    ConnectionClosed,
}
pub enum TearDownReason {}
