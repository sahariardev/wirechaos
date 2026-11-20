use crate::relay::classification::{classify, Direction, MessageKind};
use crate::relay::error::{RelayError, TeardownReason};
use crate::relay::reader::{Frame, FrameRead};
use crate::relay::sessions::RelaySession;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum PumpOutcome {
    Continue,
    Stop(TeardownReason),
}

impl RelaySession {
    #[allow(dead_code)]
    pub(crate) async fn pump_one(
        &mut self,
        direction: Direction,
    ) -> Result<PumpOutcome, RelayError> {
        let frame = match direction {
            Direction::FrontendToBackend => {
                self.frontend_reader
                    .next_frame(&mut self.frontend_read)
                    .await?
            }
            Direction::BackendToFrontend => {
                self.backend_reader
                    .next_frame(&mut self.backend_read)
                    .await?
            }
        };

        match frame {
            None => Ok(PumpOutcome::Stop(TeardownReason::Unknown)),
            Some(FrameRead::Complete(frame)) => self.forward_one(direction, frame).await,
            Some(FrameRead::Stream(header)) => {

                Err(RelayError::Protocol {
                    code: "0A000",
                    message: format!(
                        "streamed relay message ({} bytes) is not implemented until task 6.15",
                        header.body_len
                    ),
                })
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) async fn forward_one(
        &mut self,
        direction: Direction,
        frame: Frame,
    ) -> Result<PumpOutcome, RelayError> {
        let info = classify(direction, frame.header.type_byte);
        self.state.observe(&info, &frame)?;
        let flush_now = matches!(info.kind, MessageKind::Flush | MessageKind::Terminate);

        match direction {
            Direction::FrontendToBackend => {
                self.backend_writer
                    .write_frame(&mut self.backend_write, &frame)
                    .await?;
                if flush_now {
                    self.backend_writer.flush(&mut self.backend_write).await?;
                }
            }
            Direction::BackendToFrontend => {
                self.frontend_writer
                    .write_frame(&mut self.frontend_write, &frame)
                    .await?;
                if flush_now {
                    self.frontend_writer.flush(&mut self.frontend_write).await?;
                }
            }
        }

        Ok(PumpOutcome::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::buffer_pool::MultiBufferPool;
    use crate::proxy::config::Config;
    use crate::relay::config::RelayConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
    use tokio::time::{timeout, Duration};

    const F2B: Direction = Direction::FrontendToBackend;
    const B2F: Direction = Direction::BackendToFrontend;

    fn msg(type_byte: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + body.len());
        out.push(type_byte);
        out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn relay_config(yaml: Option<&str>) -> Arc<RelayConfig> {
        let config = match yaml {
            Some(text) => Config::from_yaml(text).expect("valid YAML"),
            None => Config::default(),
        };
        Arc::new(RelayConfig::from_config(&config).expect("valid relay limits"))
    }

    struct Harness {
        session: RelaySession,
        client_write: DuplexStream,
        client_read: DuplexStream,
        server_write: DuplexStream,
        server_read: DuplexStream,
    }

    fn harness_with_config(config: Arc<RelayConfig>) -> Harness {
        let (frontend_read, client_write) = tokio::io::duplex(4096);
        let (frontend_write, client_read) = tokio::io::duplex(4096);
        let (backend_read, server_write) = tokio::io::duplex(4096);
        let (backend_write, server_read) = tokio::io::duplex(4096);

        let pool = MultiBufferPool::new(4, 64 * 1024, 2);
        let session = RelaySession::new(
            Box::new(frontend_read),
            Box::new(frontend_write),
            Box::new(backend_read),
            Box::new(backend_write),
            config,
            pool,
        );

        Harness {
            session,
            client_write,
            client_read,
            server_write,
            server_read,
        }
    }

    fn harness() -> Harness {
        harness_with_config(relay_config(None))
    }

    #[tokio::test]
    async fn framed_pump_forwards_pipelined_burst_without_waiting() {
        let mut h = harness();
        let query = msg(b'Q', b"select 1\0");
        let flush = msg(b'H', b"");

        // Both frames are sent before the relay reads anything: this is the
        // pipelined case that must not wait for a backend response.
        h.client_write.write_all(&query).await.expect("query");
        h.client_write.write_all(&flush).await.expect("flush");

        assert_eq!(
            h.session.pump_one(F2B).await.expect("first"),
            PumpOutcome::Continue
        );
        assert_eq!(
            h.session.pump_one(F2B).await.expect("second"),
            PumpOutcome::Continue
        );

        let mut expected = query;
        expected.extend_from_slice(&flush);
        let mut got = vec![0u8; expected.len()];
        h.server_read.read_exact(&mut got).await.expect("forwarded");
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn multiple_frames_in_one_read_are_drained() {
        let mut h = harness();
        let mut wire = msg(b'Q', b"one\0");
        wire.extend_from_slice(&msg(b'H', b""));
        wire.extend_from_slice(&msg(b'Q', b"three\0"));
        h.client_write.write_all(&wire).await.expect("burst");

        for _ in 0..3 {
            assert_eq!(
                h.session.pump_one(F2B).await.expect("frame"),
                PumpOutcome::Continue
            );
        }

        let mut got = vec![0u8; wire.len()];
        h.server_read
            .read_exact(&mut got)
            .await
            .expect("all frames");
        assert_eq!(got, wire);
    }

    #[tokio::test]
    async fn zero_body_frames_pass() {
        let mut h = harness();
        let flush = msg(b'H', b"");
        h.client_write.write_all(&flush).await.expect("flush");

        assert_eq!(
            h.session.pump_one(F2B).await.expect("pump"),
            PumpOutcome::Continue
        );

        let mut got = vec![0u8; 5];
        h.server_read
            .read_exact(&mut got)
            .await
            .expect("five bytes");
        assert_eq!(got, flush);
    }

    #[tokio::test]
    async fn async_messages_keep_their_position() {
        let mut h = harness();
        let notice = msg(b'N', b"note\0");
        let row = msg(b'D', b"row");
        let complete = msg(b'C', b"SELECT 1\0");
        let mut wire = notice.clone();
        wire.extend_from_slice(&row);
        wire.extend_from_slice(&complete);
        h.server_write
            .write_all(&wire)
            .await
            .expect("backend burst");

        for _ in 0..3 {
            assert_eq!(
                h.session.pump_one(B2F).await.expect("frame"),
                PumpOutcome::Continue
            );
        }

        let mut got = vec![0u8; wire.len()];
        h.client_read
            .read_exact(&mut got)
            .await
            .expect("client bytes");
        assert_eq!(got, wire);
    }

    #[tokio::test]
    async fn pump_one_returns_after_one_message() {
        let mut h = harness();
        let first = msg(b'Q', b"first\0");
        let second = msg(b'Q', b"second\0");
        h.client_write
            .write_all(&first)
            .await
            .expect("first queued");
        h.client_write
            .write_all(&second)
            .await
            .expect("second queued");

        assert_eq!(
            h.session.pump_one(F2B).await.expect("pump"),
            PumpOutcome::Continue
        );

        let mut got = vec![0u8; first.len()];
        h.server_read
            .read_exact(&mut got)
            .await
            .expect("first frame");
        assert_eq!(got, first);

        // The second frame must still be unread: pump_one handles exactly one
        // message and returns.
        let mut probe = [0u8; 1];
        let extra = timeout(Duration::from_millis(20), h.server_read.read(&mut probe)).await;
        assert!(extra.is_err(), "pump_one forwarded more than one frame");
    }

    #[tokio::test]
    async fn partial_frame_is_never_forwarded() {
        let mut h = harness();
        let wire = msg(b'Q', b"partial body");
        let split = 5 + 3;

        h.client_write
            .write_all(&wire[..split])
            .await
            .expect("partial");

        let waiting = timeout(Duration::from_millis(20), h.session.pump_one(F2B)).await;
        assert!(waiting.is_err(), "partial frame must not be forwarded");

        h.client_write
            .write_all(&wire[split..])
            .await
            .expect("rest");

        assert_eq!(
            h.session.pump_one(F2B).await.expect("complete"),
            PumpOutcome::Continue
        );

        let mut got = vec![0u8; wire.len()];
        h.server_read
            .read_exact(&mut got)
            .await
            .expect("full frame");
        assert_eq!(got, wire);
    }

    #[tokio::test]
    async fn clean_eof_returns_stop() {
        let mut h = harness();
        drop(h.client_write);

        assert_eq!(
            h.session.pump_one(F2B).await.expect("clean eof"),
            PumpOutcome::Stop(TeardownReason::Unknown)
        );
    }

    #[tokio::test]
    async fn eof_mid_frame_is_a_typed_error() {
        let mut h = harness();
        let mut wire = msg(b'Q', b"truncated");
        wire.truncate(5 + 2);
        h.client_write.write_all(&wire).await.expect("partial");
        drop(h.client_write);

        let err = h.session.pump_one(F2B).await.expect_err("truncated frame");
        assert!(matches!(err, RelayError::UnexpectedEof { context: "body" }));
    }

    #[tokio::test]
    async fn framed_pump_returns_typed_errors_for_streams() {
        // 4-byte bucket forces an 8-byte body onto the streamed path.
        let config = relay_config(Some(
            "limits:\n  max_message_size: 1024\n  pool_max_bucket: 4\n  max_inflight_bytes: 16\n  capture_query_text: false\n  max_captured_query_bytes: 0\n",
        ));
        let mut h = harness_with_config(config);

        h.client_write
            .write_all(&msg(b'd', b"01234567"))
            .await
            .expect("stream frame");

        let err = h.session.pump_one(F2B).await.expect_err("streaming");
        assert!(matches!(err, RelayError::Protocol { code: "0A000", .. }));
    }

    struct TrackingWriter {
        inner: DuplexStream,
        flushes: Arc<AtomicUsize>,
    }

    impl AsyncWrite for TrackingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let me = self.get_mut();
            std::pin::Pin::new(&mut me.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let me = self.get_mut();
            me.flushes.fetch_add(1, Ordering::Relaxed);
            std::pin::Pin::new(&mut me.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn flush_is_written_immediately() {
        let (frontend_read, mut client_write) = tokio::io::duplex(4096);
        let (frontend_write, _client_read) = tokio::io::duplex(4096);
        let (backend_read, _server_write) = tokio::io::duplex(4096);
        let (backend_inner, _server_read) = tokio::io::duplex(4096);
        let flushes = Arc::new(AtomicUsize::new(0));

        let mut session = RelaySession::new(
            Box::new(frontend_read),
            Box::new(frontend_write),
            Box::new(backend_read),
            Box::new(TrackingWriter {
                inner: backend_inner,
                flushes: Arc::clone(&flushes),
            }),
            relay_config(None),
            MultiBufferPool::new(4, 64 * 1024, 2),
        );

        client_write
            .write_all(&msg(b'H', b""))
            .await
            .expect("flush frame");

        assert_eq!(
            session.pump_one(F2B).await.expect("pump"),
            PumpOutcome::Continue
        );
        assert!(
            flushes.load(Ordering::Relaxed) > 0,
            "H must force an immediate writer flush"
        );
    }
}
