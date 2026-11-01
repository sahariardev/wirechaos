pub enum RelayError {
    InvalidMessageLength { length: usize },
    MessageTooLong { length: usize, max_length: usize },
}
pub enum TearDownReason {}
