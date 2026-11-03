use crate::proxy::buffer_pool::{MultiBufferPool, PooledBytes};
use crate::relay::error::RelayError;
use crate::relay::header::FrameHeader;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) enum FrameBody {
    Empty,
    Bytes(PooledBytes),
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
    max_message_size: usize,
    pool: Arc<MultiBufferPool>,
}

impl FrameReader {
    pub(crate) fn with_pool(max_message_size: usize, pool: Arc<MultiBufferPool>) -> Self {
        Self {
            max_message_size,
            pool,
        }
    }

    pub(crate) async fn next_frame<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<FrameRead>, RelayError> {
        let (type_byte, len) = self.read_type_len(reader).await?.unwrap();

        if len < 4 {
            return Err(RelayError::InvalidMessageLength { length: len });
        }

        if len == 4 {
            return Ok(Some(FrameRead::Complete(Frame {
                body: FrameBody::Empty,
                header: FrameHeader {
                    type_byte,
                    body_len: len,
                },
            })));
        }

        if len > self.max_message_size {
            return Ok(Some(FrameRead::Stream(StreamHeader {
                type_byte,
                body_len: len,
            })));
        }

        let mut buff = self.pool.get(len);
        reader
            .read_exact(&mut buff)
            .await
            .map_err(|_| RelayError::ConnectionClosed)?;

        Ok(Some(FrameRead::Complete(Frame {
            body: FrameBody::Bytes(buff),
            header: FrameHeader {
                type_byte,
                body_len: len,
            },
        })))
    }

    async fn read_type_len<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<(u8, usize)>, RelayError> {
        //todo:: return Ok none when send 0 and no other bytes
        let mut buf = [0u8; 5];
        reader
            .read_exact(&mut buf)
            .await
            .map_err(|_| RelayError::ConnectionClosed)?;

        let type_byte = buf[0];
        let len = u32::from_be_bytes(buf[1..5].try_into().unwrap()) as usize;

        Ok(Some((type_byte, len)))
    }
}
