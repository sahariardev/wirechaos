use crate::relay::error::RelayError;
use crate::relay::header::FrameHeader;
use crate::relay::reader::FrameRead::Stream;
use tokio::io::{AsyncRead, AsyncReadExt};
use crate::proxy::buffer_pool::PooledBytes;

pub(crate) enum FrameBody {
    Empty,
    Bytes(Vec<u8>),
}

pub(crate) struct Frame {
    pub(crate) header: FrameHeader,
    pub(crate) body: FrameBody,
}

pub(crate) struct StreamHeader {
    pub(crate) type_byte: u8,
    pub(crate) body_len: usize,
}

pub(crate) enum FrameRead {
    Complete(Frame),
    Stream(StreamHeader),
}

pub(crate) struct FrameReader {
    buffer: PooledBytes,
    max_message_size: usize,
    start: usize,
    end: usize,
}

impl FrameReader {
    pub(crate) fn new(max_message_size: usize, buffer: PooledBytes) -> Self {
        Self {
            buffer,
            max_message_size,
            start: 0,
            end: 0,
        }
    }

    pub(crate) fn available(&self) -> usize {
        self.end - self.start
    }

    pub(crate) async fn next_frame<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<FrameRead>, RelayError> {
        while self.available() < 5 {
            let n = self.fill(reader).await?;
            if n == 0 {
                if self.available() == 0 {
                    return Ok(None);
                }

                return Err(RelayError::ConnectionClosed);
            }
        }

        let type_byte = self.buffer[self.start];
        self.start += 1;

        let len = u32::from_be_bytes(self.buffer[self.start..self.start + 4].try_into().unwrap())
            as usize;

        self.start += 4;

        if len < 4 {
            return Err(RelayError::InvalidMessageLength { length: len });
        }

        let len = len - 4;

        if len > self.max_message_size {
            let stream_header = StreamHeader {
                type_byte,
                body_len: len,
            };

            return Ok(Some(Stream(stream_header)));
        }

        let frame_header = FrameHeader {
            type_byte,
            body_len: len,
        };

        if len == 0 {
            return Ok(Some(FrameRead::Complete(Frame {
                header: frame_header,
                body: FrameBody::Empty,
            })));
        }

        while self.available() < len {
            self.fill(reader).await?;
        }

        let frame_body = FrameBody::Bytes(self.buffer[self.start..self.start + len].to_vec());

        if self.available() < len {
            return Err(RelayError::ConnectionClosed);
        }

        self.start += len;

        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }

        Ok(Some(FrameRead::Complete(Frame {
            header: frame_header,
            body: frame_body,
        })))
    }

    async fn fill<R: AsyncRead + Unpin>(&mut self, reader: &mut R) -> Result<usize, RelayError> {
        if self.end == self.buffer.len() {
            self.buffer.copy_within(self.start..self.end, 0);
            self.end = self.end - self.start;
            self.start = 0;
        }

        let n = reader
            .read(&mut self.buffer[self.end..])
            .await
            .map_err(|_| RelayError::ConnectionClosed)?;

        self.end += n;

        Ok(n)
    }
}
