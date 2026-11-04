pub enum RelayError {
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
    Shutdown(TearDownReason),
}
pub enum TearDownReason {}

impl RelayError {
    pub(crate) fn sqlstate(&self) -> Option<&'static str> {
        todo!("implement this")
    }

    pub(crate) fn client_message(&self) -> &str {
        todo!("implement this")
    }
}

pub(crate) fn fatal_error_response(code: &str, message: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(b'S');
    body.extend_from_slice("FATAL".as_bytes());
    body.push(b'C');
    body.extend_from_slice(code.as_bytes());
    body.push(b'M');
    body.extend_from_slice(message.as_bytes());
    let mut data = Vec::new();
    data.push(b'E');
    data.extend_from_slice(&body.len().to_be_bytes());
    data.extend_from_slice(&body);

    data
}
