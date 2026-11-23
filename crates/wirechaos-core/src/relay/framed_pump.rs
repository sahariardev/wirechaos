use crate::relay::classification::{classify, Direction, MessageKind};
use crate::relay::degrade::BodyAccess;
use crate::relay::error::{RelayError, TeardownReason};
use crate::relay::header::{FrameHeader, ReadPath};
use crate::relay::hook::{FrameContext, HookDecision};
use crate::relay::reader::{Frame, FrameBody, FrameRead, StreamHeader};
use crate::relay::sessions::RelaySession;
use crate::relay::suppression::SuppressionAction;

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
            Some(FrameRead::Complete(frame)) => {
                let read_path = if frame.header.body_len == 0 {
                    ReadPath::HeaderOnly
                } else {
                    ReadPath::Pooled
                };
                self.counters.observe_read_path(direction, read_path);
                self.forward_one(direction, frame).await
            }
            Some(FrameRead::Stream(header)) => {
                self.counters
                    .observe_read_path(direction, ReadPath::Streamed);
                self.forward_stream(direction, header).await
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

        // Suppression is checked before the hook: a hidden backend window is
        // still observed for state, but no hook and no write see it.
        if direction == Direction::BackendToFrontend
            && self.suppression.observe_backend(&info) == SuppressionAction::Drop
        {
            return Ok(PumpOutcome::Continue);
        }

        let ctx = FrameContext {
            direction,
            info,
            mode: self.mode,
            phase: self.state.phase.phase(),
            txn: self.state.txn,
            copy: self.state.copy,
            pending: self.state.pending_count(),
            body_access: BodyAccess::Complete,
            last_query: self.state.last_query(),
        };

        let flush_now = matches!(info.kind, MessageKind::Flush | MessageKind::Terminate);
        let decision = self.hooks.on_frame(&ctx, &frame)?;

        match decision {
            HookDecision::Pass => {
                self.write_frame(direction, &frame, flush_now).await?;
            }
            HookDecision::Forward { delay } => {
                if let Some(delay) = delay {
                    tokio::time::sleep(delay).await;
                }
                self.write_frame(direction, &frame, flush_now).await?;
            }
            HookDecision::Emit { frames } => {
                for replacement in frames {
                    let replacement_kind = classify(direction, replacement.header.type_byte);
                    let replacement_flush = matches!(
                        replacement_kind.kind,
                        MessageKind::Flush | MessageKind::Terminate
                    );

                    self.write_frame(direction, &replacement, flush_now || replacement_flush)
                        .await?;
                }
            }
            HookDecision::SuppressResponse => {
                if direction == Direction::FrontendToBackend {
                    self.suppression.arm();
                    self.write_frame(direction, &frame, flush_now).await?;
                } else {
                    return Err(RelayError::Protocol {
                        code: "XX000",
                        message: "SuppressResponse is only valid for frontend frames".to_owned(),
                    });
                }
            }
            HookDecision::Drop => {}
            HookDecision::Terminate => {
                return Ok(PumpOutcome::Stop(TeardownReason::ChaosTerminate))
            }
        }

        Ok(PumpOutcome::Continue)
    }

    async fn write_frame(
        &mut self,
        direction: Direction,
        frame: &Frame,
        flush_now: bool,
    ) -> Result<(), RelayError> {
        match direction {
            Direction::FrontendToBackend => {
                self.backend_writer
                    .write_frame(&mut self.backend_write, frame)
                    .await?;
                if flush_now {
                    self.backend_writer.flush(&mut self.backend_write).await?;
                }
            }
            Direction::BackendToFrontend => {
                self.frontend_writer
                    .write_frame(&mut self.frontend_write, frame)
                    .await?;
                if flush_now {
                    self.frontend_writer.flush(&mut self.frontend_write).await?;
                }
            }
        }

        self.counters
            .observe_written(direction, 5 + frame.header.body_len);
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) async fn forward_stream(
        &mut self,
        direction: Direction,
        header: StreamHeader,
    ) -> Result<PumpOutcome, RelayError> {
        let info = classify(direction, header.type_byte);

        let header_frame = Frame {
            header: FrameHeader {
                type_byte: header.type_byte,
                body_len: header.body_len,
            },
            body: FrameBody::Empty,
        };

        self.state.observe(&info, &header_frame)?;

        // A streamed backend frame still participates in suppression. Drain it
        // so framing stays aligned, then write nothing.
        if direction == Direction::BackendToFrontend
            && self.suppression.observe_backend(&info) == SuppressionAction::Drop
        {
            self.drain_stream(direction, header.body_len).await?;
            return Ok(PumpOutcome::Continue);
        }

        let ctx = FrameContext {
            direction,
            info,
            mode: self.mode,
            phase: self.state.phase.phase(),
            txn: self.state.txn,
            copy: self.state.copy,
            pending: self.state.pending_count(),
            body_access: BodyAccess::Streamed,
            last_query: self.state.last_query(),
        };

        let decision = self.hooks.on_frame(&ctx, &header_frame)?;

        match decision {
            HookDecision::Pass => self.stream_original(direction, header).await,
            HookDecision::Forward { delay } => {
                if let Some(delay) = delay {
                    tokio::time::sleep(delay).await;
                }

                self.stream_original(direction, header).await
            }
            HookDecision::Drop => {
                self.drain_stream(direction, header.body_len).await?;
                Ok(PumpOutcome::Continue)
            }
            HookDecision::Terminate => Ok(PumpOutcome::Stop(TeardownReason::ChaosTerminate)),
            HookDecision::Emit { .. } => Err(RelayError::Protocol {
                code: "0A000",
                message: "cannot emit a replacement for a streamed body".to_owned(),
            }),
            HookDecision::SuppressResponse => {
                if direction == Direction::BackendToFrontend {
                    self.suppression.arm();
                    self.drain_stream(direction, header.body_len).await?;
                    Ok(PumpOutcome::Continue)
                } else {
                    Err(RelayError::Protocol {
                        code: "XX000",
                        message: "SuppressResponse is only valid for backend frames".to_owned(),
                    })
                }
            }
        }
    }

    async fn drain_stream(
        &mut self,
        direction: Direction,
        mut remaining: usize,
    ) -> Result<(), RelayError> {
        while remaining > 0 {
            let chunk = match direction {
                Direction::FrontendToBackend => {
                    self.frontend_reader
                        .read_body_chunk(&mut self.frontend_read, remaining)
                        .await?
                }
                Direction::BackendToFrontend => {
                    self.backend_reader
                        .read_body_chunk(&mut self.backend_read, remaining)
                        .await?
                }
            };

            remaining -= chunk.len();
        }

        match direction {
            Direction::FrontendToBackend => self.frontend_reader.finish_stream(),
            Direction::BackendToFrontend => self.backend_reader.finish_stream(),
        }

        Ok(())
    }

    async fn stream_original(
        &mut self,
        direction: Direction,
        header: StreamHeader,
    ) -> Result<PumpOutcome, RelayError> {
        let mut remaining = header.body_len;
        match direction {
            Direction::FrontendToBackend => {
                self.backend_writer
                    .write_header(&mut self.backend_write, &header)
                    .await?;

                while remaining > 0 {
                    let chunk = self
                        .frontend_reader
                        .read_body_chunk(&mut self.frontend_read, remaining)
                        .await?;

                    let chunk_len = chunk.len();
                    self.backend_writer
                        .write_body_chunk(&mut self.backend_write, &chunk)
                        .await?;
                    remaining -= chunk_len;
                }

                self.frontend_reader.finish_stream();
            }

            Direction::BackendToFrontend => {
                self.frontend_writer
                    .write_header(&mut self.frontend_write, &header)
                    .await?;

                while remaining > 0 {
                    let chunk = self
                        .backend_reader
                        .read_body_chunk(&mut self.backend_read, remaining)
                        .await?;

                    let chunk_len = chunk.len();
                    self.frontend_writer
                        .write_body_chunk(&mut self.frontend_write, &chunk)
                        .await?;
                    remaining -= chunk_len;
                }

                self.backend_reader.finish_stream();
            }
        }

        self.counters
            .observe_written(direction, 5 + header.body_len);
        Ok(PumpOutcome::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::buffer_pool::MultiBufferPool;
    use crate::proxy::config::Config;
    use crate::relay::config::RelayConfig;
    use crate::relay::hook::RelayHooks;
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
        let session = RelaySession::for_test(
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
    async fn streamed_body_is_forwarded_in_chunks() {
        // 4-byte bucket forces an 8-byte body onto the streamed path.
        let config = relay_config(Some(
            "limits:\n  max_message_size: 1024\n  pool_max_bucket: 4\n  max_inflight_bytes: 16\n  capture_query_text: false\n  max_captured_query_bytes: 0\n",
        ));
        let mut h = harness_with_config(config);
        let wire = msg(b'd', b"01234567");
        h.client_write.write_all(&wire).await.expect("stream frame");

        assert_eq!(
            h.session.pump_one(F2B).await.expect("streaming"),
            PumpOutcome::Continue
        );

        let mut got = vec![0u8; wire.len()];
        h.server_read
            .read_exact(&mut got)
            .await
            .expect("streamed bytes");
        assert_eq!(got, wire);
    }

    #[tokio::test]
    async fn large_streamed_body_uses_bounded_chunks() {
        let config = relay_config(Some(
            "limits:\n  max_message_size: 4194304\n  pool_max_bucket: 4096\n  max_inflight_bytes: 8192\n  capture_query_text: false\n  max_captured_query_bytes: 0\n",
        ));
        let (frontend_read, mut client_write) = tokio::io::duplex(64 * 1024);
        let (frontend_write, _client_read) = tokio::io::duplex(64 * 1024);
        let (backend_read, _server_write) = tokio::io::duplex(64 * 1024);
        let (backend_write, mut server_read) = tokio::io::duplex(64 * 1024);
        let mut session = RelaySession::for_test(
            Box::new(frontend_read),
            Box::new(frontend_write),
            Box::new(backend_read),
            Box::new(backend_write),
            config,
            MultiBufferPool::new(4, 64 * 1024, 2),
        );

        let body = vec![0x5a_u8; 512 * 1024];
        let wire = msg(b'd', &body);
        let expected = wire.clone();
        let pump = tokio::spawn(async move { session.pump_one(F2B).await });

        let mut got = vec![0u8; expected.len()];
        let write = async {
            client_write.write_all(&wire).await.expect("large stream");
            drop(client_write);
        };
        let read = async {
            server_read
                .read_exact(&mut got)
                .await
                .expect("streamed output");
        };
        tokio::join!(write, read);

        let outcome = timeout(Duration::from_secs(5), pump)
            .await
            .expect("large stream finished")
            .expect("task");
        assert_eq!(outcome.expect("pump"), PumpOutcome::Continue);
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn framing_violation_closes_with_typed_08p01() {
        let mut h = harness();
        h.client_write
            .write_all(&[b'Q', 0, 0, 0, 2])
            .await
            .expect("bad header");

        let err = h.session.pump_one(F2B).await.expect_err("bad length");
        assert!(matches!(
            err,
            RelayError::InvalidMessageLength { length: 2 }
        ));
        assert_eq!(err.sqlstate(), Some("08P01"));
    }

    #[tokio::test]
    async fn hostile_length_is_rejected_before_body_allocation() {
        let mut h = harness();
        let mut header = [0u8; 5];
        header[0] = b'Q';
        header[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
        h.client_write.write_all(&header).await.expect("hostile");

        let err = h.session.pump_one(F2B).await.expect_err("too large");
        assert!(matches!(err, RelayError::MessageTooLarge { .. }));
    }

    #[tokio::test]
    async fn hook_is_invoked_once_per_message() {
        struct CountingHooks(Arc<AtomicUsize>);
        impl RelayHooks for CountingHooks {
            fn on_frame(
                &mut self,
                _ctx: &FrameContext<'_>,
                _frame: &Frame,
            ) -> Result<HookDecision, RelayError> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(HookDecision::Pass)
            }
        }

        let mut h = harness();
        let calls = Arc::new(AtomicUsize::new(0));
        h.session
            .with_hooks(Box::new(CountingHooks(Arc::clone(&calls))));

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

        assert_eq!(calls.load(Ordering::Relaxed), 3);
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

        let mut session = RelaySession::for_test(
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
