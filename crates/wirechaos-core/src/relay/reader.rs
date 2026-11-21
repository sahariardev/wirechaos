use crate::proxy::buffer_pool::{MultiBufferPool, PooledBytes};
use crate::relay::error::RelayError;
use crate::relay::header::{read_path_for, validate_header, FrameHeader, ReadPath};
use bytes::{Buf, BytesMut};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt};

#[allow(dead_code)]
pub(crate) enum FrameBody {
    Empty,
    Pooled(PooledBytes),
}

#[allow(dead_code)]
pub(crate) struct Frame {
    pub(crate) header: FrameHeader,
    pub(crate) body: FrameBody,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct StreamHeader {
    pub(crate) type_byte: u8,
    pub(crate) body_len: usize,
}

#[allow(dead_code)]
pub(crate) enum FrameRead {
    Complete(Frame),
    Stream(StreamHeader),
}

#[allow(dead_code)]
pub(crate) struct FrameReader {
    max_message_size: usize,
    pool_max_bucket: usize,
    pool: Arc<MultiBufferPool>,
    partial: BytesMut,
    in_progress: Option<BodyProgress>,
    pending_stream: Option<StreamHeader>,
}

struct BodyProgress {
    header: FrameHeader,
    buffer: PooledBytes,
    filled: usize,
}

const HEADER_LEN: usize = 5;

#[allow(dead_code)]
fn map_io(e: std::io::Error, context: &'static str) -> RelayError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        RelayError::UnexpectedEof { context }
    } else {
        RelayError::Io(e)
    }
}

impl FrameReader {
    #[allow(dead_code)]
    pub(crate) fn with_pool(max_message_size: usize, pool: Arc<MultiBufferPool>) -> Self {
        let pool_max_bucket = pool.max_capacity();
        Self::with_limits(max_message_size, pool_max_bucket, pool)
    }

    #[allow(dead_code)]
    pub(crate) fn with_limits(
        max_message_size: usize,
        pool_max_bucket: usize,
        pool: Arc<MultiBufferPool>,
    ) -> Self {
        let pool_max_bucket = pool_max_bucket.min(pool.max_capacity());
        Self {
            max_message_size,
            pool_max_bucket,
            pool,
            partial: BytesMut::new(),
            in_progress: None,
            pending_stream: None,
        }
    }

    async fn fill_to<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
        target: usize,
        context: &'static str,
    ) -> Result<bool, RelayError> {
        while self.partial.len() < target {
            let missing = target - self.partial.len();
            let mut limited = (&mut *reader).take(missing as u64);
            match limited.read_buf(&mut self.partial).await {
                Ok(0) => return Ok(false),
                Ok(_) => {}
                Err(e) => return Err(map_io(e, context)),
            }
        }
        Ok(true)
    }
    
    pub(crate) fn is_at_boundary(&self) -> bool {
        todo!("implement this")
    }

    #[allow(dead_code)]
    pub(crate) async fn next_frame<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<FrameRead>, RelayError> {
        if let Some(stream) = self.pending_stream {
            return Err(RelayError::Protocol {
                code: "0A000",
                message: format!(
                    "streamed body of {} bytes must be consumed before the next frame",
                    stream.body_len
                ),
            });
        }

        if self.in_progress.is_some() {
            let frame = self.finish_body(reader).await?;
            return Ok(Some(FrameRead::Complete(frame)));
        }

        if !self.fill_to(reader, HEADER_LEN, "header").await? {
            if self.partial.is_empty() {
                return Ok(None);
            }
            self.partial.clear();
            return Err(RelayError::UnexpectedEof { context: "header" });
        }

        let header_buf = [
            self.partial[0],
            self.partial[1],
            self.partial[2],
            self.partial[3],
            self.partial[4],
        ];
        let header = match validate_header(&header_buf, self.max_message_size) {
            Ok(header) => header,
            Err(error) => {
                // An invalid length makes the rest of the stream unparseable.
                self.partial.clear();
                return Err(error);
            }
        };
        self.partial.advance(HEADER_LEN);

        match read_path_for(header.body_len, self.pool_max_bucket) {
            ReadPath::HeaderOnly => Ok(Some(FrameRead::Complete(Frame {
                header,
                body: FrameBody::Empty,
            }))),
            ReadPath::Pooled => {
                let buffer = self.pool.get(header.body_len);
                self.in_progress = Some(BodyProgress {
                    header,
                    buffer,
                    filled: 0,
                });
                let frame = self.finish_body(reader).await?;
                Ok(Some(FrameRead::Complete(frame)))
            }
            ReadPath::Streamed => {
                let stream = StreamHeader {
                    type_byte: header.type_byte,
                    body_len: header.body_len,
                };
                self.pending_stream = Some(stream);
                Ok(Some(FrameRead::Stream(stream)))
            }
        }
    }

    async fn finish_body<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Frame, RelayError> {
        loop {
            let (body_len, filled) = match self.in_progress.as_ref() {
                Some(progress) => (progress.header.body_len, progress.filled),
                None => {
                    return Err(RelayError::Protocol {
                        code: "XX000",
                        message: "body read resumed without in-progress state".to_owned(),
                    });
                }
            };
            if filled >= body_len {
                break;
            }

            let copied = {
                let progress = match self.in_progress.as_mut() {
                    Some(progress) => progress,
                    None => {
                        return Err(RelayError::Protocol {
                            code: "XX000",
                            message: "body read lost in-progress state".to_owned(),
                        });
                    }
                };
                let available = self.partial.len().min(body_len - progress.filled);
                if available > 0 {
                    let start = progress.filled;
                    progress.buffer[start..start + available]
                        .copy_from_slice(&self.partial[..available]);
                    progress.filled += available;
                }
                available
            };
            if copied > 0 {
                self.partial.advance(copied);
                continue;
            }

            let read = {
                let progress = match self.in_progress.as_mut() {
                    Some(progress) => progress,
                    None => {
                        return Err(RelayError::Protocol {
                            code: "XX000",
                            message: "body read lost in-progress state".to_owned(),
                        });
                    }
                };
                let start = progress.filled;
                reader.read(&mut progress.buffer[start..body_len]).await
            };

            match read {
                Ok(0) => {
                    self.in_progress = None;
                    return Err(RelayError::UnexpectedEof { context: "body" });
                }
                Ok(n) => {
                    if let Some(progress) = self.in_progress.as_mut() {
                        progress.filled += n;
                    }
                }
                Err(error) => {
                    // A broken body cannot be resumed.
                    self.in_progress = None;
                    return Err(map_io(error, "body"));
                }
            }
        }

        let progress = match self.in_progress.take() {
            Some(progress) => progress,
            None => {
                return Err(RelayError::Protocol {
                    code: "XX000",
                    message: "completed body disappeared from reader state".to_owned(),
                });
            }
        };
        Ok(Frame {
            header: progress.header,
            body: FrameBody::Pooled(progress.buffer),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Error as IoError;
    use tokio::io::AsyncWriteExt;
    use tokio::time::{timeout, Duration};

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
        max_chunk: usize,
    }

    impl MemReader {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                pos: 0,
                max_chunk: usize::MAX,
            }
        }

        fn chunked(data: Vec<u8>, max_chunk: usize) -> Self {
            Self {
                data,
                pos: 0,
                max_chunk,
            }
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
            let n = buf.remaining().min(remaining.len()).min(me.max_chunk);
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

        // The pool still has a usable pre-allocated bucket: the reader did not
        // rent (and leak) a buffer for the empty body.
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

    #[tokio::test]
    async fn multiple_frames_in_one_read_are_drained() {
        let pool = MultiBufferPool::new(4, 64, 1);
        let mut r = FrameReader::with_pool(4096, Arc::clone(&pool));

        let mut wire = msg(b'Q', b"one");
        wire.extend_from_slice(&msg(b'H', b""));
        wire.extend_from_slice(&msg(b'D', b"three"));

        let mut cur = MemReader::new(wire);

        let first = r.next_frame(&mut cur).await.expect("first").expect("frame");
        let second = r
            .next_frame(&mut cur)
            .await
            .expect("second")
            .expect("frame");
        let third = r.next_frame(&mut cur).await.expect("third").expect("frame");
        let end = r.next_frame(&mut cur).await.expect("eof");

        match first {
            FrameRead::Complete(f) => assert_eq!(body_bytes(&f), b"one"),
            _ => panic!("expected complete first"),
        }
        match second {
            FrameRead::Complete(f) => {
                assert_eq!(f.header.type_byte, b'H');
                assert_eq!(body_bytes(&f), b"");
            }
            _ => panic!("expected complete second"),
        }
        match third {
            FrameRead::Complete(f) => assert_eq!(body_bytes(&f), b"three"),
            _ => panic!("expected complete third"),
        }
        assert!(end.is_none());
    }

    #[tokio::test]
    async fn zero_length_body_is_a_frame() {
        let pool = MultiBufferPool::new(4, 64, 1);
        let mut r = FrameReader::with_pool(4096, Arc::clone(&pool));
        let mut cur = MemReader::new(msg(b'S', b""));

        match r.next_frame(&mut cur).await.expect("empty frame") {
            Some(FrameRead::Complete(f)) => {
                assert_eq!(f.header.type_byte, b'S');
                assert_eq!(f.header.body_len, 0);
                assert!(matches!(f.body, FrameBody::Empty));
            }
            _ => panic!("empty body must be a frame, not EOF"),
        }
        assert!(r.next_frame(&mut cur).await.expect("clean eof").is_none());
    }

    #[tokio::test]
    async fn eof_mid_frame_is_a_typed_error() {
        let pool = MultiBufferPool::new(4, 64, 1);
        let mut r = FrameReader::with_pool(4096, Arc::clone(&pool));

        let mut wire = msg(b'Q', &[0u8; 8]);
        wire.truncate(5 + 3);
        let mut cur = MemReader::new(wire);

        let err = match r.next_frame(&mut cur).await {
            Ok(_frame) => panic!("truncated body returned a frame"),
            Err(error) => error,
        };
        assert!(matches!(err, RelayError::UnexpectedEof { context: "body" }));
    }

    #[tokio::test]
    async fn chunking_never_changes_message_boundaries() {
        let pool = MultiBufferPool::new(4, 64, 2);
        let mut wire = msg(b'Q', b"alpha");
        wire.extend_from_slice(&msg(b'H', b""));
        wire.extend_from_slice(&msg(b'd', b"0123456789"));

        for chunk in [1usize, 2, 3, 5, 7, 64] {
            let mut r = FrameReader::with_pool(4096, Arc::clone(&pool));
            let mut cur = MemReader::chunked(wire.clone(), chunk);
            let mut seen = Vec::new();

            loop {
                match r.next_frame(&mut cur).await.expect("chunked frame") {
                    Some(FrameRead::Complete(f)) => {
                        seen.push((f.header.type_byte, body_bytes(&f)));
                    }
                    Some(FrameRead::Stream(_)) => panic!("unexpected stream"),
                    None => break,
                }
            }

            assert_eq!(seen.len(), 3, "chunk size {chunk} lost a frame");
            assert_eq!(seen[0], (b'Q', b"alpha".to_vec()));
            assert_eq!(seen[1], (b'H', Vec::new()));
            assert_eq!(seen[2], (b'd', b"0123456789".to_vec()));
        }
    }

    #[tokio::test]
    async fn cancelled_header_read_preserves_buffered_bytes() {
        let pool = MultiBufferPool::new(4, 64, 1);
        let mut r = FrameReader::with_pool(4096, Arc::clone(&pool));
        let (mut relay_side, mut peer) = tokio::io::duplex(64);

        let wire = msg(b'Q', b"cancel me");
        peer.write_all(&wire[..3]).await.expect("partial header");

        // This read blocks after consuming three header bytes. Dropping the
        // future must not discard them.
        let first = timeout(Duration::from_millis(20), r.next_frame(&mut relay_side)).await;
        assert!(first.is_err(), "partial header must not produce a frame");

        peer.write_all(&wire[3..]).await.expect("rest of frame");

        let frame = timeout(Duration::from_millis(200), r.next_frame(&mut relay_side))
            .await
            .expect("second read completes")
            .expect("frame result")
            .expect("complete frame");
        match frame {
            FrameRead::Complete(f) => assert_eq!(body_bytes(&f), b"cancel me"),
            _ => panic!("expected complete frame after cancellation"),
        }
    }

    #[tokio::test]
    async fn cancelled_body_read_resumes_without_losing_bytes() {
        let pool = MultiBufferPool::new(4, 64, 1);
        let mut r = FrameReader::with_pool(4096, Arc::clone(&pool));
        let (mut relay_side, mut peer) = tokio::io::duplex(64);

        let wire = msg(b'Q', b"cancel body");
        // Header plus two body bytes: the reader rents a buffer and then
        // blocks mid-body.
        peer.write_all(&wire[..7]).await.expect("header + body");

        let first = timeout(Duration::from_millis(20), r.next_frame(&mut relay_side)).await;
        assert!(first.is_err(), "partial body must not produce a frame");
        assert!(
            r.in_progress.is_some(),
            "the rented body must survive cancellation"
        );

        peer.write_all(&wire[7..]).await.expect("rest of body");

        let frame = timeout(Duration::from_millis(200), r.next_frame(&mut relay_side))
            .await
            .expect("second read completes")
            .expect("frame result")
            .expect("complete frame");
        match frame {
            FrameRead::Complete(f) => assert_eq!(body_bytes(&f), b"cancel body"),
            _ => panic!("expected complete frame after body cancellation"),
        }
    }
}
