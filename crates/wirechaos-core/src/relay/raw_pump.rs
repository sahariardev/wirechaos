use crate::proxy::buffer_pool::MultiBufferPool;
use crate::relay::RelayError;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[allow(dead_code)]
pub(crate) type ShutdownSignal = tokio::sync::watch::Receiver<bool>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum RawStop {
    Eof,
    Shutdown,
}

#[allow(dead_code)]
pub(crate) async fn copy_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    shutdown: &mut ShutdownSignal,
    pool: Arc<MultiBufferPool>,
    pool_size: usize,
) -> Result<RawStop, RelayError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let chunk_size = pool_size.min(pool.max_capacity());
    if chunk_size == 0 {
        return Err(RelayError::Protocol {
            code: "XX000",
            message: "raw pump buffer size must be greater than zero".to_owned(),
        });
    }

    let mut buffer = pool.get(chunk_size);

    loop {
        if *shutdown.borrow() {
            return Ok(RawStop::Shutdown);
        }


        let n = tokio::select! {
            biased;

            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(RawStop::Shutdown);
                }
                continue;
            }

            result = reader.read(&mut buffer[..]) => result.map_err(RelayError::Io)?,
        };

        if n == 0 {
            writer.shutdown().await.map_err(RelayError::Io)?;
            return Ok(RawStop::Eof);
        }

        writer
            .write_all(&buffer[..n])
            .await
            .map_err(RelayError::Io)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error as IoError, ErrorKind};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};
    use tokio::time::{timeout, Duration};

    fn pool() -> Arc<MultiBufferPool> {
        MultiBufferPool::new(4, 64, 2)
    }

    #[tokio::test]
    async fn raw_direction_copies_exactly() {
        let (mut relay_read, mut peer_write) = tokio::io::duplex(64);
        let (mut relay_write, mut peer_read) = tokio::io::duplex(64);
        let (_tx, mut shutdown) = tokio::sync::watch::channel(false);

        let payload = b"raw bytes are never framed";
        peer_write.write_all(payload).await.expect("input");
        drop(peer_write);

        let stop = copy_direction(&mut relay_read, &mut relay_write, &mut shutdown, pool(), 4)
            .await
            .expect("copy");

        assert_eq!(stop, RawStop::Eof);
        let mut output = Vec::new();
        peer_read.read_to_end(&mut output).await.expect("collect");
        assert_eq!(output, payload);
    }

    #[tokio::test]
    async fn clean_eof_shuts_down_the_writer() {
        let mut empty = tokio::io::empty();
        let (inner, _peer) = tokio::io::duplex(64);
        let shutdown_called = Arc::new(AtomicBool::new(false));
        let mut writer = TrackingWriter {
            inner,
            shutdown_called: Arc::clone(&shutdown_called),
        };
        let (_tx, mut shutdown) = tokio::sync::watch::channel(false);

        let stop = copy_direction(&mut empty, &mut writer, &mut shutdown, pool(), 8)
            .await
            .expect("copy");

        assert_eq!(stop, RawStop::Eof);
        assert!(
            shutdown_called.load(Ordering::SeqCst),
            "clean EOF must half-close the destination"
        );
    }

    #[tokio::test]
    async fn raw_direction_maps_write_failures() {
        let mut input = tokio::io::repeat(7u8);
        let mut failing = FailingWriter;
        let (_tx, mut shutdown) = tokio::sync::watch::channel(false);

        let err = copy_direction(&mut input, &mut failing, &mut shutdown, pool(), 8)
            .await
            .expect_err("broken pipe");
        assert!(matches!(err, RelayError::Io(_)));
    }

    #[tokio::test]
    async fn raw_cancellation_preserves_written_bytes() {
        let (mut relay_read, mut peer_write) = tokio::io::duplex(64);
        let (mut relay_write, mut peer_read) = tokio::io::duplex(64);
        let (tx, mut shutdown) = tokio::sync::watch::channel(false);

        peer_write.write_all(b"abc").await.expect("input");

        let task = tokio::spawn(async move {
            copy_direction(&mut relay_read, &mut relay_write, &mut shutdown, pool(), 16).await
        });

        // Wait until the chunk is on the wire, then cancel. The bytes already
        // written must stay written.
        let mut first = [0u8; 3];
        peer_read.read_exact(&mut first).await.expect("first chunk");
        assert_eq!(&first, b"abc");

        tx.send(true).expect("raise shutdown");
        let stop = timeout(Duration::from_secs(1), task)
            .await
            .expect("copy task finished")
            .expect("task did not panic")
            .expect("copy result");

        assert_eq!(stop, RawStop::Shutdown);
        assert_eq!(&first, b"abc");
    }

    struct TrackingWriter {
        inner: tokio::io::DuplexStream,
        shutdown_called: Arc<AtomicBool>,
    }

    impl AsyncWrite for TrackingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let me = self.get_mut();
            Pin::new(&mut me.inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            let me = self.get_mut();
            me.shutdown_called.store(true, Ordering::SeqCst);
            Pin::new(&mut me.inner).poll_shutdown(cx)
        }
    }

    struct FailingWriter;

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Err(IoError::new(ErrorKind::BrokenPipe, "boom")))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}
