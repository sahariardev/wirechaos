use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum TeardownReason {
    Unknown,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum RelayError {
    NotImplemented {
        task: &'static str,
        what: &'static str,
    },
    InvalidMessageLength {
        length: usize,
    },
    MessageTooLarge {
        length: usize,
        max: usize,
    },
    UnexpectedEof {
        context: &'static str,
    },
    Protocol {
        code: &'static str,
        message: String,
    },
    Io(std::io::Error),
    InFlightExceeded {
        requested: usize,
        current: usize,
        max: usize,
    },
    Shutdown(TeardownReason),
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented { task, what } => {
                write!(f, "not implemented (task {task}): {what}")
            }
            Self::InvalidMessageLength { length } => {
                write!(f, "invalid message length: {length}")
            }
            Self::MessageTooLarge { length, max } => {
                write!(f, "message length {length} exceeds maximum {max}")
            }
            Self::UnexpectedEof { context } => {
                write!(f, "unexpected end of message ({context})")
            }
            Self::Protocol { code, message } => {
                write!(f, "protocol error {code}: {message}")
            }
            Self::Io(inner) => write!(f, "io error: {inner}"),
            Self::InFlightExceeded {
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
            | Self::MessageTooLarge { .. }
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
            Self::MessageTooLarge { .. } => "message length exceeds the configured maximum",
            Self::UnexpectedEof { .. } => "unexpected end of message",
            Self::Protocol { message, .. } => message,
            Self::Io(_) => "io error",
            Self::InFlightExceeded { .. } => "in-flight budget exceeded",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::header::validate_header;

    fn parse_error_response(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
        assert_eq!(bytes[0], b'E');
        let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        assert_eq!(len + 1, bytes.len());
        let mut fields = Vec::new();
        let mut pos = 5usize;
        while pos < bytes.len() {
            let code = bytes[pos];
            pos += 1;
            if code == 0 {
                break;
            }
            let start = pos;
            while pos < bytes.len() && bytes[pos] != 0 {
                pos += 1;
            }
            fields.push((code, bytes[start..pos].to_vec()));
            pos += 1;
        }
        fields
    }

    #[test]
    fn fatal_error_response_has_severity_code_and_message() {
        let bytes = fatal_error_response("08P01", "invalid message length");
        let fields = parse_error_response(&bytes);
        assert!(fields.contains(&(b'S', b"FATAL".to_vec())));
        assert!(fields.contains(&(b'C', b"08P01".to_vec())));
        assert!(fields.contains(&(b'M', b"invalid message length".to_vec())));
    }

    #[test]
    fn invalid_length_maps_to_08p01() {
        let e = RelayError::InvalidMessageLength { length: 2 };
        assert_eq!(e.sqlstate(), Some("08P01"));
        assert_eq!(e.client_message(), "invalid message length");

        let e = RelayError::MessageTooLarge {
            length: 9999,
            max: 4096,
        };
        assert_eq!(e.sqlstate(), Some("08P01"));
        assert_eq!(
            e.client_message(),
            "message length exceeds the configured maximum"
        );

        let e = RelayError::UnexpectedEof { context: "body" };
        assert_eq!(e.sqlstate(), Some("08P01"));
        assert_eq!(e.client_message(), "unexpected end of message");
    }

    #[test]
    fn backend_death_maps_to_57p01() {
        let e = RelayError::Protocol {
            code: "57P01",
            message: "server closed the connection unexpectedly".to_owned(),
        };
        assert_eq!(e.sqlstate(), Some("57P01"));
        assert_eq!(
            e.client_message(),
            "server closed the connection unexpectedly"
        );
    }

    #[test]
    fn budget_failure_is_not_a_protocol_error() {
        let e = RelayError::InFlightExceeded {
            requested: 100,
            current: 90,
            max: 95,
        };
        assert_eq!(e.sqlstate(), None);
        assert_eq!(e.client_message(), "in-flight budget exceeded");
        let s = RelayError::Shutdown(TeardownReason::Unknown);
        assert_eq!(s.sqlstate(), None);
        let n = RelayError::NotImplemented {
            task: "6.6",
            what: "x",
        };
        assert_eq!(n.sqlstate(), None);
    }

    #[test]
    fn error_text_contains_no_query_or_secret() {
        let secret_query = "SELECT password FROM users WHERE secret='hunter2'";
        let e = RelayError::InvalidMessageLength { length: 2 };
        assert!(!e.client_message().contains(secret_query));
        assert!(!e.to_string().contains(secret_query));
        let e = RelayError::MessageTooLarge {
            length: 9999,
            max: 4096,
        };
        assert!(!e.client_message().contains("SELECT"));
        let e = RelayError::UnexpectedEof { context: "body" };
        assert!(!e.to_string().contains("password"));
        let bytes = fatal_error_response("08P01", "invalid message length");
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("SELECT"));
        assert!(!text.contains("password"));
        assert!(!text.contains("hunter2"));
    }

    #[test]
    fn unknown_type_is_not_an_error() {
        let mut h = [0u8; 5];
        h[0] = 0xFF;
        h[1..5].copy_from_slice(&8u32.to_be_bytes());
        let parsed = validate_header(&h, 4096).expect("unknown type is valid");
        assert_eq!(parsed.type_byte, 0xFF);
        assert_eq!(parsed.body_len, 4);
    }
}
