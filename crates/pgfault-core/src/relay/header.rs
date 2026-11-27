use crate::relay::error::RelayError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct FrameHeader {
    pub(crate) type_byte: u8,
    pub(crate) body_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum ReadPath {
    HeaderOnly,
    Pooled,
    Streamed,
}

#[allow(dead_code)]
pub(crate) fn validate_header(
    header: &[u8; 5],
    max_message_size: usize,
) -> Result<FrameHeader, RelayError> {
    let type_byte = header[0];
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;

    if length < 4 {
        return Err(RelayError::InvalidMessageLength { length });
    }

    if length > max_message_size {
        return Err(RelayError::MessageTooLarge {
            length,
            max: max_message_size,
        });
    }

    Ok(FrameHeader {
        type_byte,
        body_len: length - 4,
    })
}

#[allow(dead_code)]
pub(crate) fn read_path_for(body_len: usize, pool_max_bucket: usize) -> ReadPath {
    match body_len {
        0 => ReadPath::HeaderOnly,
        len if len <= pool_max_bucket => ReadPath::Pooled,
        _ => ReadPath::Streamed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_with_len(type_byte: u8, length: u32) -> [u8; 5] {
        let mut h = [0u8; 5];
        h[0] = type_byte;
        h[1..5].copy_from_slice(&length.to_be_bytes());
        h
    }

    fn header_with_body(type_byte: u8, body: &[u8]) -> [u8; 5] {
        header_with_len(type_byte, (body.len() + 4) as u32)
    }

    #[test]
    fn framing_validation_table() {
        let cap = 4096;

        let below = header_with_len(b'Q', 2);
        let err = validate_header(&below, cap).expect_err("length < 4");
        assert!(matches!(
            err,
            RelayError::InvalidMessageLength { length: 2 }
        ));

        let empty = header_with_len(b'H', 4);
        let parsed = validate_header(&empty, cap).expect("empty body is legal");
        assert_eq!(parsed.type_byte, b'H');
        assert_eq!(parsed.body_len, 0);

        let normal = header_with_body(b'Q', b"select 1");
        let parsed = validate_header(&normal, cap).expect("normal body");
        assert_eq!(parsed.type_byte, b'Q');
        assert_eq!(parsed.body_len, 8);

        let above = header_with_len(b'Q', cap as u32 + 5);
        let err = validate_header(&above, cap).expect_err("above cap");
        assert!(matches!(
            err,
            RelayError::MessageTooLarge { length, max: 4096 } if length == 4096 + 5
        ));
    }

    #[test]
    fn zero_length_body_is_not_a_missing_message() {
        let h = header_with_body(b'H', b"");
        let parsed = validate_header(&h, 4096).expect("empty body");
        assert_eq!(parsed.type_byte, b'H');
        assert_eq!(parsed.body_len, 0);
        assert_eq!(read_path_for(parsed.body_len, 65536), ReadPath::HeaderOnly);
    }

    #[test]
    fn read_path_selection_by_body_size() {
        assert_eq!(read_path_for(0, 65536), ReadPath::HeaderOnly);
        assert_eq!(read_path_for(1, 65536), ReadPath::Pooled);
        assert_eq!(read_path_for(64 * 1024, 65536), ReadPath::Pooled);
        assert_eq!(read_path_for(64 * 1024 + 1, 65536), ReadPath::Streamed);
        assert_eq!(read_path_for(300 * 1024 * 1024, 65536), ReadPath::Streamed);
    }

    #[test]
    fn unknown_type_byte_still_has_a_valid_header() {
        let h = header_with_body(0xFF, b"payload");
        let parsed = validate_header(&h, 4096).expect("unknown type byte is valid");
        assert_eq!(parsed.type_byte, 0xFF);
        assert_eq!(parsed.body_len, 7);
    }

    #[test]
    fn truncated_header_is_not_parsed_as_a_frame() {
        let short: Vec<u8> = vec![b'Q', 0, 0];
        assert!(short.len() < 5);
        let as_array: Result<[u8; 5], _> = short.as_slice().try_into();
        assert!(as_array.is_err());
    }
}
