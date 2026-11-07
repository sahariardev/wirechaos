use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum TeardownReason {
    Unknown,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum RelayError {
    InvalidMessageLength {
        length: usize,
    },
    MessageTooLong {
        length: usize,
        max_length: usize,
    },
    ConnectionClosed,
    NotImplemented {
        task: &'static str,
        what: &'static str,
    },
    UnexpectedEof {
        context: &'static str,
    },
    Protocol {
        code: &'static str,
        message: &'static str,
    },
    Io(std::io::Error),
    InFlightExceed {
        requested: usize,
        current: usize,
        max: usize,
    },
    Shutdown(TeardownReason),
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMessageLength { length } => {
                write!(f, "invalid message length: {length}")
            }
            Self::MessageTooLong { length, max_length } => {
                write!(f, "message length {length} exceeds maximum {max_length}")
            }
            Self::ConnectionClosed => write!(f, "connection closed"),
            Self::NotImplemented { task, what } => {
                write!(f, "not implemented (task {task}): {what}")
            }
            Self::UnexpectedEof { context } => {
                write!(f, "unexpected end of message ({context})")
            }
            Self::Protocol { code, message } => {
                write!(f, "protocol error {code}: {message}")
            }
            Self::Io(inner) => write!(f, "io error: {inner}"),
            Self::InFlightExceed {
                requested,
                current,
                max,
            } => write!(
                f,
                "in-flight budget exceeded: requested {requested}, current {current}, max {max}"
            ),
            Self::Shutdown(reason) => write!(f, "shutdown: {reason:?}"),
        }
    }
}

impl std::error::Error for RelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(inner) => Some(inner),
            _ => None,
        }
    }
}

impl RelayError {
    #[allow(dead_code)]
    pub(crate) fn sqlstate(&self) -> Option<&'static str> {
        match self {
            Self::InvalidMessageLength { .. }
            | Self::MessageTooLong { .. }
            | Self::UnexpectedEof { .. } => Some("08P01"),
            Self::Protocol { code, .. } => Some(code),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn client_message(&self) -> &str {
        match self {
            Self::NotImplemented { .. } => "not implemented",
            Self::InvalidMessageLength { .. } => "invalid message length",
            Self::MessageTooLong { .. } => "message length exceeds the configured maximum",
            Self::ConnectionClosed => "connection closed",
            Self::UnexpectedEof { .. } => "unexpected end of message",
            Self::Protocol { message, .. } => message,
            Self::Io(_) => "io error",
            Self::InFlightExceed { .. } => "in-flight budget exceeded",
            Self::Shutdown(_) => "shutdown",
        }
    }
}

#[allow(dead_code)]
pub(crate) fn fatal_error_response(code: &str, message: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(b'S');
    body.extend_from_slice("FATAL".as_bytes());
    body.push(0);
    body.push(b'C');
    body.extend_from_slice(code.as_bytes());
    body.push(0);
    body.push(b'M');
    body.extend_from_slice(message.as_bytes());
    body.push(0);
    let len = (body.len() as u32) + 4;
    let mut data = Vec::new();
    data.push(b'E');
    data.extend_from_slice(&len.to_be_bytes());
    data.extend_from_slice(&body);
    data
}
