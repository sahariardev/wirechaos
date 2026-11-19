use crate::proxy::buffer_pool::PooledBytes;
use crate::relay::error::RelayError;
use crate::relay::reader::{Frame, FrameBody, StreamHeader};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[allow(dead_code)]
pub(crate) struct FrameWriter {}

impl FrameWriter {
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        frame: &Frame,
    ) -> Result<(), RelayError> {
        let len = (frame.header.body_len + 4) as u32;
        let mut header = [0u8; 5];
        header[0] = frame.header.type_byte;
        header[1..5].copy_from_slice(&len.to_be_bytes());
        writer.write_all(&header).await.map_err(RelayError::Io)?;
        match &frame.body {
            FrameBody::Pooled(bytes) => {
                writer
                    .write_all(bytes.as_slice())
                    .await
                    .map_err(RelayError::Io)?;
            }
            FrameBody::Empty => {}
        }
        Ok(())
    }

    pub(crate) async fn write_streamed<W, R>(
        &self,
        writer: &mut W,
        reader: &mut R,
        stream_header: &StreamHeader,
        buffer: PooledBytes,
    ) -> Result<(), RelayError>
    where
        W: AsyncWrite + Unpin,
        R: AsyncRead + Unpin,
    {
        let len = (stream_header.body_len + 4) as u32;
        let mut header = [0u8; 5];
        header[0] = stream_header.type_byte;
        header[1..5].copy_from_slice(&len.to_be_bytes());
        writer.write_all(&header).await.map_err(RelayError::Io)?;
        self.handle_stream_writing(reader, writer, buffer, stream_header.body_len)
            .await?;

        Ok(())
    }

    async fn handle_stream_writing<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        mut buffer: PooledBytes,
        mut total_size: usize,
    ) -> Result<(), RelayError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            if total_size == 0 {
                break;
            }

            let mut read_max_length = buffer.len();
            if total_size < read_max_length {
                read_max_length = total_size;
            }

            let read_data_size = reader
                .read_exact(&mut buffer[0..read_max_length])
                .await
                .map_err(|e| RelayError::Io(e))?;

            total_size -= read_data_size;

            if read_data_size == 0 {
                return Err(RelayError::UnexpectedEof {
                    context: "Unexpected end of stream",
                });
            }

            writer
                .write_all(&buffer[0..read_data_size])
                .await
                .map_err(|e| RelayError::Io(e))?;
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) async fn flush<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> Result<(), RelayError> {
        writer.flush().await.map_err(RelayError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::buffer_pool::MultiBufferPool;
    use crate::relay::header::FrameHeader;
    use std::io::{Error as IoError, ErrorKind};
    use std::sync::Arc;

    fn test_pool() -> Arc<MultiBufferPool> {
        MultiBufferPool::new(4, 64, 1)
    }

    struct MemWriter {
        buf: Vec<u8>,
        flushed: bool,
    }

    impl AsyncWrite for MemWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.get_mut().buf.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.get_mut().flushed = true;
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    struct ChunkedWriter {
        buf: Vec<u8>,
        max_write: usize,
    }

    impl AsyncWrite for ChunkedWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let me = self.get_mut();
            let n = buf.len().min(me.max_write);
            me.buf.extend_from_slice(&buf[..n]);
            std::task::Poll::Ready(Ok(n))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    struct FailingWriter;

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(IoError::new(ErrorKind::BrokenPipe, "boom")))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(IoError::new(ErrorKind::BrokenPipe, "boom")))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn empty_frame(type_byte: u8) -> Frame {
        Frame {
            header: FrameHeader {
                type_byte,
                body_len: 0,
            },
            body: FrameBody::Empty,
        }
    }

    fn pooled_frame(pool: &Arc<MultiBufferPool>, type_byte: u8, body: &[u8]) -> Frame {
        let mut b = pool.get(body.len());
        b.copy_from_slice(body);
        Frame {
            header: FrameHeader {
                type_byte,
                body_len: body.len(),
            },
            body: FrameBody::Pooled(b),
        }
    }

    #[tokio::test]
    async fn zero_body_writes_exactly_five_bytes() {
        let mut w = FrameWriter::new();
        let mut out = MemWriter {
            buf: Vec::new(),
            flushed: false,
        };
        w.write_frame(&mut out, &empty_frame(b'H'))
            .await
            .expect("write");
        assert_eq!(out.buf, vec![b'H', 0, 0, 0, 4]);
    }

    #[tokio::test]
    async fn pooled_body_is_byte_identical() {
        let pool = test_pool();
        let mut w = FrameWriter::new();
        let body = b"select 1";
        let frame = pooled_frame(&pool, b'Q', body);
        let mut out = MemWriter {
            buf: Vec::new(),
            flushed: false,
        };
        w.write_frame(&mut out, &frame).await.expect("write");
        let mut expected = Vec::new();
        expected.push(b'Q');
        expected.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        expected.extend_from_slice(body);
        assert_eq!(out.buf, expected);
    }

    #[tokio::test]
    async fn write_frame_preserves_message_boundaries() {
        let pool = test_pool();
        let mut w = FrameWriter::new();
        let f1 = pooled_frame(&pool, b'Q', b"one");
        let f2 = empty_frame(b'H');
        let mut out = MemWriter {
            buf: Vec::new(),
            flushed: false,
        };
        w.write_frame(&mut out, &f1).await.expect("first");
        w.write_frame(&mut out, &f2).await.expect("second");
        let mut expected = Vec::new();
        expected.push(b'Q');
        expected.extend_from_slice(&(7u32).to_be_bytes());
        expected.extend_from_slice(b"one");
        expected.push(b'H');
        expected.extend_from_slice(&(4u32).to_be_bytes());
        assert_eq!(out.buf, expected);
    }

    #[tokio::test]
    async fn flush_is_explicit_and_immediate() {
        let pool = test_pool();
        let mut w = FrameWriter::new();
        let frame = pooled_frame(&pool, b'X', b"");
        let mut out = MemWriter {
            buf: Vec::new(),
            flushed: false,
        };
        w.write_frame(&mut out, &frame).await.expect("write");
        assert!(!out.flushed);
        w.flush(&mut out).await.expect("flush");
        assert!(out.flushed);
    }

    #[tokio::test]
    async fn partial_write_retries_without_losing_bytes() {
        let pool = test_pool();
        let mut w = FrameWriter::new();
        let body = b"hello world";
        let frame = pooled_frame(&pool, b'Q', body);
        let mut out = ChunkedWriter {
            buf: Vec::new(),
            max_write: 2,
        };
        w.write_frame(&mut out, &frame).await.expect("write");
        let mut expected = Vec::new();
        expected.push(b'Q');
        expected.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        expected.extend_from_slice(body);
        assert_eq!(out.buf, expected);
    }

    #[tokio::test]
    async fn writer_error_is_typed() {
        let mut w = FrameWriter::new();
        let frame = empty_frame(b'H');
        let mut failing = FailingWriter;
        let err = w
            .write_frame(&mut failing, &frame)
            .await
            .expect_err("failing writer");
        assert!(matches!(err, RelayError::Io(_)));
    }
}
