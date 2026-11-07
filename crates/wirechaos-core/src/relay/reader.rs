use crate::proxy::buffer_pool::{MultiBufferPool, PooledBytes};
use crate::relay::error::RelayError;
use crate::relay::header::{read_path_for, validate_header, FrameHeader, ReadPath};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) enum FrameBody {
    Empty,
    Pooled(PooledBytes),
}

pub(crate) struct Frame {
    pub(crate) header: FrameHeader,
    pub(crate) body: FrameBody,
}

#[derive(Clone, Copy, PartialEq, Eq)]
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
    pool_max_bucket: usize,
    pool: Arc<MultiBufferPool>,
}

fn map_io(e: std::io::Error, context: &'static str) -> RelayError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        RelayError::UnexpectedEof { context }
    } else {
        RelayError::Io(e)
    }
}

impl FrameReader {
    pub(crate) fn with_pool(max_message_size: usize, pool: Arc<MultiBufferPool>) -> Self {
        let pool_max_bucket = pool.max_capacity();
        Self {
            max_message_size,
            pool_max_bucket,
            pool,
        }
    }

    async fn read_header<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<[u8; 5]>, RelayError> {
        let mut first = [0u8; 1];
        match reader.read(&mut first).await {
            Ok(0) => Ok(None),
            Ok(_) => {
                let mut buf = [0u8; 5];
                buf[0] = first[0];
                reader
                    .read_exact(&mut buf[1..])
                    .await
                    .map_err(|e| map_io(e, "header"))?;
                Ok(Some(buf))
            }
            Err(e) => Err(map_io(e, "header")),
        }
    }

    pub(crate) async fn next_frame<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<FrameRead>, RelayError> {
        let Some(header_buf) = self.read_header(reader).await? else {
            return Ok(None);
        };
        let header = validate_header(&header_buf, self.max_message_size)?;
        match read_path_for(header.body_len, self.pool_max_bucket) {
            ReadPath::HeaderOnly => Ok(Some(FrameRead::Complete(Frame {
                header,
                body: FrameBody::Empty,
            }))),
            ReadPath::Pooled => {
                let mut buf = self.pool.get(header.body_len);
                reader
                    .read_exact(&mut buf)
                    .await
                    .map_err(|e| map_io(e, "body"))?;
                Ok(Some(FrameRead::Complete(Frame {
                    header,
                    body: FrameBody::Pooled(buf),
                })))
            }
            ReadPath::Streamed => Ok(Some(FrameRead::Stream(StreamHeader {
                type_byte: header.type_byte,
                body_len: header.body_len,
            }))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Error as IoError;

    fn msg(type_byte: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + body.len());
        out.push(type_byte);
        out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn header_only(type_byte: u8, body_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(5);
        out.push(type_byte);
        out.extend_from_slice(&((body_len + 4) as u32).to_be_bytes());
        out
    }

    fn body_bytes(frame: &Frame) -> Vec<u8> {
        match &frame.body {
            FrameBody::Empty => Vec::new(),
            FrameBody::Pooled(b) => b.as_slice().to_vec(),
        }
    }

    struct MemReader {
        data: Vec<u8>,
        pos: usize,
    }

    impl MemReader {
        fn new(data: Vec<u8>) -> Self {
            Self { data, pos: 0 }
        }
    }

    impl AsyncRead for MemReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let me = self.get_mut();
            if me.pos >= me.data.len() {
                return std::task::Poll::Ready(Ok(()));
            }
            let remaining = &me.data[me.pos..];
            let n = buf.remaining().min(remaining.len());
            buf.put_slice(&remaining[..n]);
            me.pos += n;
            std::task::Poll::Ready(Ok(()))
        }
    }

    struct FailingReader {
        data: Vec<u8>,
        pos: usize,
        fail_after: usize,
    }

    impl AsyncRead for FailingReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let me = self.get_mut();
            if me.pos >= me.fail_after || me.pos >= me.data.len() {
                return std::task::Poll::Ready(Err(IoError::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof",
                )));
            }
            let remaining = &me.data[me.pos..];
            let n = buf
                .remaining()
                .min(remaining.len())
                .min(me.fail_after - me.pos);
            buf.put_slice(&remaining[..n]);
            me.pos += n;
            std::task::Poll::Ready(Ok(()))
        }
    }

    struct SlowBodyReader {
        header: Vec<u8>,
        pos: usize,
    }

    impl AsyncRead for SlowBodyReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let me = self.get_mut();
            if me.pos >= me.header.len() {
                return std::task::Poll::Pending;
            }
            let remaining = &me.header[me.pos..];
            let n = buf.remaining().min(remaining.len());
            buf.put_slice(&remaining[..n]);
            me.pos += n;
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn exact_bucket_and_non_power_of_two_bodies_are_served() {
        let pool = MultiBufferPool::new(4, 64, 1);
        let mut r = FrameReader::with_pool(4096, Arc::clone(&pool));

        let wire = msg(b'Q', &[7u8; 8]);
        let mut cur = MemReader::new(wire);
        match r.next_frame(&mut cur).await.expect("exact bucket") {
            Some(FrameRead::Complete(f)) => {
                assert_eq!(f.header.type_byte, b'Q');
                assert_eq!(f.header.body_len, 8);
                assert_eq!(body_bytes(&f), vec![7u8; 8]);
            }
            other => panic!(
                "expected Complete, got Stream or None: {}",
                matches!(other, Some(FrameRead::Stream(_)))
            ),
        }

        let wire = msg(b'Q', &[9u8; 9]);
        let mut cur = MemReader::new(wire);
        match r.next_frame(&mut cur).await.expect("non power of two") {
            Some(FrameRead::Complete(f)) => {
                assert_eq!(f.header.body_len, 9);
                assert_eq!(body_bytes(&f), vec![9u8; 9]);
            }
            _ => panic!("expected Complete for non power of two"),
        }

        let wire = msg(b'Q', &[5u8; 63]);
        let mut cur = MemReader::new(wire);
        match r.next_frame(&mut cur).await.expect("between buckets") {
            Some(FrameRead::Complete(f)) => {
                assert_eq!(f.header.body_len, 63);
                assert_eq!(body_bytes(&f), vec![5u8; 63]);
            }
            _ => panic!("expected Complete for 63"),
        }

        let wire = msg(b'Q', &[3u8; 64]);
        let mut cur = MemReader::new(wire);
        match r.next_frame(&mut cur).await.expect("exact max bucket") {
            Some(FrameRead::Complete(f)) => {
                assert_eq!(f.header.body_len, 64);
                assert_eq!(body_bytes(&f), vec![3u8; 64]);
            }
            _ => panic!("expected Complete for 64"),
        }
    }

    #[tokio::test]
    async fn header_only_frame_rents_nothing() {
        let pool = MultiBufferPool::new(4, 64, 1);
        let mut r = FrameReader::with_pool(4096, Arc::clone(&pool));

        let wire = msg(b'H', b"");
        let mut cur = MemReader::new(wire);
        match r.next_frame(&mut cur).await.expect("header only") {
            Some(FrameRead::Complete(f)) => {
                assert_eq!(f.header.type_byte, b'H');
                assert_eq!(f.header.body_len, 0);
                assert!(matches!(f.body, FrameBody::Empty));
            }
            _ => panic!("expected Complete for header only"),
        }

        let mut next = pool.get(8);
        next.copy_from_slice(&[1u8; 8]);
    }

    #[tokio::test]
    async fn streamed_body_returns_no_pooled_buffer() {
        let pool = MultiBufferPool::new(4, 64, 1);
        let mut r = FrameReader::with_pool(1 << 20, Arc::clone(&pool));

        let wire = header_only(b'd', 100);
        let mut cur = MemReader::new(wire);
        match r.next_frame(&mut cur).await.expect("streamed") {
            Some(FrameRead::Stream(s)) => {
                assert_eq!(s.type_byte, b'd');
                assert_eq!(s.body_len, 100);
            }
            _ => panic!("expected Stream"),
        }

        let mut next = pool.get(8);
        next.copy_from_slice(&[2u8; 8]);
    }

    #[tokio::test]
    async fn read_error_and_cancel_return_the_buffer() {
        let pool = MultiBufferPool::new(4, 64, 1);
        let mut r = FrameReader::with_pool(4096, Arc::clone(&pool));

        let mut wire = msg(b'Q', &[0u8; 8]);
        wire.truncate(5 + 3);
        let mut failing = FailingReader {
            data: wire,
            pos: 0,
            fail_after: 5 + 3,
        };
        let err = match r.next_frame(&mut failing).await {
            Err(e) => e,
            Ok(_) => panic!("expected mid-body eof"),
        };
        assert!(matches!(err, RelayError::UnexpectedEof { context: "body" }));

        let mut again = pool.get(8);
        again.copy_from_slice(&[4u8; 8]);

        let mut r2 = FrameReader::with_pool(4096, Arc::clone(&pool));
        let header = header_only(b'Q', 16);
        let mut slow = SlowBodyReader { header, pos: 0 };
        let res = tokio::time::timeout(
            std::time::Duration::from_millis(10),
            r2.next_frame(&mut slow),
        )
        .await;
        assert!(res.is_err());

        let mut after_cancel = pool.get(8);
        after_cancel.copy_from_slice(&[6u8; 8]);
    }

    #[tokio::test]
    async fn pool_rented_count_returns_to_baseline() {
        let pool = MultiBufferPool::new(4, 64, 2);
        let mut r = FrameReader::with_pool(4096, Arc::clone(&pool));

        for i in 0..10u8 {
            let wire = msg(b'Q', &[i; 8]);
            let mut cur = MemReader::new(wire);
            match r.next_frame(&mut cur).await.expect("loop frame") {
                Some(FrameRead::Complete(f)) => {
                    assert_eq!(body_bytes(&f), vec![i; 8]);
                    drop(f);
                }
                _ => panic!("expected Complete in loop"),
            }
        }

        for _ in 0..4 {
            let mut b = pool.get(8);
            assert_eq!(b.len(), 8);
            b.copy_from_slice(&[0u8; 8]);
        }
    }
}
