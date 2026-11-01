use crate::relay::error::RelayError;

pub(crate) struct FrameHeader {
    pub(crate) type_byte: u8,
    pub(crate) body_len: usize,
}

pub(crate) enum ReadPath {
    HeaderOnly,
    Pooled,
    Streamed,
}

impl FrameHeader {
    pub(crate) fn from_bytes(
        header: &[u8; 5],
        max_message_size: usize,
    ) -> Result<Self, RelayError> {
        let type_byte = header[0];
        let body_len = u32::from_be_bytes(header[1..5].try_into().unwrap()) as usize;
        if body_len < 4 {
            return Err(RelayError::InvalidMessageLength { length: body_len });
        }

        if body_len > max_message_size {
            return Err(RelayError::MessageTooLong {
                length: body_len - 4,
                max_length: max_message_size,
            });
        }

        Ok(Self {
            type_byte,
            body_len,
        })
    }

    pub(crate) fn read_path(&self, pooled_max_size: usize) -> ReadPath {
        match self.body_len {
            0 => ReadPath::HeaderOnly,
            len if len <= pooled_max_size => ReadPath::Pooled,
            _ => ReadPath::Streamed,
        }
    }
}
