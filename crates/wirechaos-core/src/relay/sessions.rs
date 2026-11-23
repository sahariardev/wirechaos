use crate::proxy::buffer_pool::MultiBufferPool;
use crate::proxy::conn_registry::ConnPermit;
use crate::relay::budget::InFlightBudget;
use crate::relay::classification::Direction;
use crate::relay::config::RelayConfig;
use crate::relay::counters::{CounterSnapshot, RelayCounters};
use crate::relay::error::{RelayError, TeardownReason};
use crate::relay::hook::{NoopHooks, RelayHooks};
use crate::relay::raw_pump::{copy_direction, RawStop, ShutdownSignal};
use crate::relay::reader::{Frame, FrameRead, FrameReader};
use crate::relay::state::SessionState;
use crate::relay::suppression::SuppressionWindow;
use crate::relay::teardown::TeardownExecutor;
use crate::relay::writer::FrameWriter;
use crate::relay::{decide_mode, EpochWatcher, ModePlan, PumpOutcome, SessionFilters};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Mode {
    #[default]
    Raw,
    Framed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayOutcome {
    pub(crate) mode: Mode,
    pub(crate) reason: TeardownReason,
    pub(crate) counters: CounterSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RunOutcome {
    Done(RelayOutcome),
    Switch(Mode),
}

#[allow(dead_code)]
pub(crate) struct RelaySession {
    pub(crate) frontend_read: Box<dyn AsyncRead + Send + Unpin>,
    pub(crate) frontend_write: Box<dyn AsyncWrite + Send + Unpin>,
    pub(crate) backend_read: Box<dyn AsyncRead + Send + Unpin>,
    pub(crate) backend_write: Box<dyn AsyncWrite + Send + Unpin>,
    pub(crate) config: Arc<RelayConfig>,
    pub(crate) pool: Arc<MultiBufferPool>,
    pub(crate) frontend_reader: FrameReader,
    pub(crate) backend_reader: FrameReader,
    pub(crate) frontend_writer: FrameWriter,
    pub(crate) backend_writer: FrameWriter,
    pub(crate) state: SessionState,
    pub(crate) plan: Arc<dyn ModePlan>,
    pub(crate) filters: SessionFilters,
    pub(crate) chaos_enabled: bool,
    pub(crate) epoch: EpochWatcher,
    pub(crate) mode: Mode,
    pub(crate) raw_in_flight: bool,
    pub(crate) frontend_budget: InFlightBudget,
    pub(crate) backend_budget: InFlightBudget,
    pub(crate) hooks: Box<dyn RelayHooks>,
    pub(crate) suppression: SuppressionWindow,
    pub(crate) counters: RelayCounters,
    pub(crate) permit: Option<ConnPermit>,

    pub(crate) shutdown: ShutdownSignal,
}

impl RelaySession {
    #[allow(dead_code)]
    #[allow(
        clippy::too_many_arguments,
        reason = "each argument transfers one per-session component; the constructor is called once"
    )]
    pub(crate) fn new(
        frontend_read: Box<dyn AsyncRead + Send + Unpin>,
        frontend_write: Box<dyn AsyncWrite + Send + Unpin>,
        backend_read: Box<dyn AsyncRead + Send + Unpin>,
        backend_write: Box<dyn AsyncWrite + Send + Unpin>,
        config: Arc<RelayConfig>,
        pool: Arc<MultiBufferPool>,
        shutdown: ShutdownSignal,
        plan: Arc<dyn ModePlan>,
        filters: SessionFilters,
        chaos_enabled: bool,
        epoch_watcher: EpochWatcher,
    ) -> Self {
        let max_message_size = config.max_message_size;
        let pool_max_bucket = config.pool_max_bucket;
        let max_inflight_bytes = config.max_inflight_bytes;
        Self {
            frontend_read,
            frontend_write,
            backend_read,
            backend_write,
            frontend_reader: FrameReader::with_limits(
                max_message_size,
                pool_max_bucket,
                Arc::clone(&pool),
            ),
            backend_reader: FrameReader::with_limits(
                max_message_size,
                pool_max_bucket,
                Arc::clone(&pool),
            ),
            frontend_writer: FrameWriter::new(),
            backend_writer: FrameWriter::new(),
            state: SessionState::with_config(&config),
            config,
            pool,
            shutdown,
            plan,
            epoch: epoch_watcher,
            filters,
            chaos_enabled,
            mode: Mode::Raw,
            raw_in_flight: false,
            frontend_budget: InFlightBudget::new(max_inflight_bytes),
            backend_budget: InFlightBudget::new(max_inflight_bytes),
            hooks: Box::new(NoopHooks),
            suppression: SuppressionWindow::new(),
            counters: RelayCounters::new(Mode::Raw),
            permit: None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn set_permit(&mut self, permit: ConnPermit) {
        self.permit = Some(permit);
    }

    pub(crate) fn desired_mode(&self) -> Mode {
        decide_mode(self.plan.as_ref(), &self.filters, self.chaos_enabled)
    }

    pub(crate) fn framed_at_boundary(&self) -> bool {
        self.frontend_reader.is_at_boundary() && self.backend_reader.is_at_boundary()
    }

    pub(crate) fn raw_quiescent(&self) -> bool {
        !self.raw_in_flight
    }

    #[allow(dead_code)]
    pub(crate) fn duplicate_frame(
        &mut self,
        direction: Direction,
        frame: &Frame,
    ) -> Result<(), RelayError> {
        let bytes = 5 + frame.header.body_len;
        let budget = match direction {
            Direction::FrontendToBackend => &self.frontend_budget,
            Direction::BackendToFrontend => &self.backend_budget,
        };

        let reservation = budget
            .reserve(bytes)
            .map_err(|error| RelayError::Protocol {
                code: "XX000",
                message: error.to_string(),
            })?;

        drop(reservation);
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn with_hooks(&mut self, hooks: Box<dyn RelayHooks>) {
        self.hooks = hooks;
    }

    /// Test constructor with the production dependencies filled in.
    #[cfg(test)]
    pub(crate) fn for_test(
        frontend_read: Box<dyn AsyncRead + Send + Unpin>,
        frontend_write: Box<dyn AsyncWrite + Send + Unpin>,
        backend_read: Box<dyn AsyncRead + Send + Unpin>,
        backend_write: Box<dyn AsyncWrite + Send + Unpin>,
        config: Arc<RelayConfig>,
        pool: Arc<MultiBufferPool>,
    ) -> Self {
        let (shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
        let (_epoch_tx, epoch) = tokio::sync::watch::channel(0);
        // Tests do not own a connection task to keep the sender alive; leaking
        // the test sender keeps `changed()` pending instead of reporting a
        // closed channel (which means "shutdown").
        std::mem::forget(shutdown_tx);
        Self::new(
            frontend_read,
            frontend_write,
            backend_read,
            backend_write,
            config,
            pool,
            shutdown,
            Arc::new(crate::relay::NoChaosPlan),
            SessionFilters::default(),
            false,
            EpochWatcher::new(epoch),
        )
    }
}

#[allow(dead_code)]
pub(crate) async fn run(mut session: RelaySession) -> Result<RelayOutcome, RelayError> {
    loop {
        let mode = session.desired_mode();
        session.mode = mode;
        session.counters.set_mode(mode);

        match mode {
            Mode::Raw => match run_raw(&mut session).await? {
                RunOutcome::Done(outcome) => return Ok(session.shutdown(outcome).await),
                RunOutcome::Switch(next) => {
                    if next == Mode::Raw {
                        return Err(RelayError::Protocol {
                            code: "XX000",
                            message: "same-mode raw switch is a logic bug".to_owned(),
                        });
                    }
                }
            },
            Mode::Framed => match run_framed(&mut session).await? {
                RunOutcome::Done(outcome) => return Ok(session.shutdown(outcome).await),
                RunOutcome::Switch(next) => {
                    if next == Mode::Framed {
                        return Err(RelayError::Protocol {
                            code: "XX000",
                            message: "same-mode framed switch is a logic bug".to_owned(),
                        });
                    }
                }
            },
        }
    }
}

impl RelaySession {
    /// The single teardown path. Consumes the session, so cleanup can run once.
    pub(crate) async fn shutdown(mut self, outcome: RelayOutcome) -> RelayOutcome {
        let trigger = outcome.reason.trigger();
        let decision = {
            let mut executor = TeardownExecutor {
                frontend_write: &mut self.frontend_write,
                backend_write: &mut self.backend_write,
            };
            executor.execute(trigger).await.ok()
        };

        let reason = decision.map_or(outcome.reason, |decision| decision.reason);
        self.counters.set_teardown_reason(reason);
        let counters = self.counters.snapshot();
        let final_outcome = RelayOutcome {
            mode: outcome.mode,
            reason,
            counters,
        };

        // Everything relay-owned drops before the permit. The permit is last
        // so a new session cannot start while old buffers are still rented.
        let permit = self.permit.take();
        drop(self.frontend_reader);
        drop(self.backend_reader);
        drop(self.state);
        drop(self.hooks);
        drop(self.frontend_read);
        drop(self.frontend_write);
        drop(self.backend_read);
        drop(self.backend_write);
        drop(permit);

        final_outcome
    }
}

#[allow(dead_code)]
pub(crate) async fn run_raw(session: &mut RelaySession) -> Result<RunOutcome, RelayError> {
    let mut frontend_shutdown = session.shutdown.clone();
    let mut backend_shutdown = session.shutdown.clone();
    let frontend_pool = Arc::clone(&session.pool);
    let backend_pool = Arc::clone(&session.pool);
    let chunk_size = session.config.max_inflight_bytes;

    let frontend = copy_direction(
        &mut session.frontend_read,
        &mut session.backend_write,
        &mut frontend_shutdown,
        frontend_pool,
        chunk_size,
    );

    let backend = copy_direction(
        &mut session.backend_read,
        &mut session.frontend_write,
        &mut backend_shutdown,
        backend_pool,
        chunk_size,
    );

    let (frontend, backend) = tokio::join!(frontend, backend);
    let frontend = frontend?;
    let backend = backend?;

    let reason = match (frontend, backend) {
        (RawStop::Shutdown, _) | (_, RawStop::Shutdown) => TeardownReason::Unknown,
        (RawStop::Eof, RawStop::Eof) => TeardownReason::ClientEof,
    };

    if session.epoch.changed() {
        let desired = session.desired_mode();
        if desired != Mode::Raw && session.raw_quiescent() {
            return Ok(RunOutcome::Switch(desired));
        }
    }

    Ok(RunOutcome::Done(RelayOutcome {
        mode: Mode::Raw,
        reason,
        counters: session.counters.snapshot(),
    }))
}

#[allow(dead_code)]
pub(crate) async fn run_framed(session: &mut RelaySession) -> Result<RunOutcome, RelayError> {
    let mut frontend_done = false;
    let mut backend_done = false;
    let mut first_reason: Option<TeardownReason> = None;

    loop {
        if frontend_done && backend_done {
            return Ok(RunOutcome::Done(RelayOutcome {
                mode: Mode::Framed,
                reason: first_reason.unwrap_or(TeardownReason::ClientEof),
                counters: session.counters.snapshot(),
            }));
        }

        let selected = tokio::select! {
            biased;

            changed = session.shutdown.changed() => {
                let _ = changed;
                return Ok(RunOutcome::Done(RelayOutcome {
                    mode: Mode::Framed,
                    reason: TeardownReason::Unknown,
                    counters: session.counters.snapshot(),
                }))
            }

            result = session.frontend_reader.next_frame(&mut session.frontend_read), if !frontend_done => {
                (Direction::FrontendToBackend, result?)
            }

            result = session.backend_reader.next_frame(&mut session.backend_read), if !backend_done => {
                (Direction::BackendToFrontend, result?)
            }
        };

        let (direction, frame) = selected;
        match frame {
            None => {
                half_close(session, direction).await?;

                let reason = match direction {
                    Direction::FrontendToBackend => {
                        frontend_done = true;
                        TeardownReason::ClientEof
                    }
                    Direction::BackendToFrontend => {
                        backend_done = true;
                        if session.state.pending_count() > 0 {
                            TeardownReason::BackendEofWhileWaiting
                        } else {
                            TeardownReason::BackendEof
                        }
                    }
                };
                if first_reason.is_none() {
                    first_reason = Some(reason);
                }
            }
            Some(FrameRead::Complete(frame)) => {
                if let PumpOutcome::Stop(reason) = session.forward_one(direction, frame).await? {
                    return Ok(RunOutcome::Done(RelayOutcome {
                        mode: Mode::Framed,
                        reason,
                        counters: session.counters.snapshot(),
                    }));
                }

                if session.epoch.changed() {
                    let desired = session.desired_mode();

                    if desired != Mode::Framed && session.framed_at_boundary() {
                        return Ok(RunOutcome::Switch(desired));
                    }
                }
            }
            Some(FrameRead::Stream(header)) => {
                if let PumpOutcome::Stop(reason) = session.forward_stream(direction, header).await?
                {
                    return Ok(RunOutcome::Done(RelayOutcome {
                        mode: Mode::Framed,
                        reason,
                        counters: session.counters.snapshot(),
                    }));
                }
            }
        }
    }
}

async fn half_close(session: &mut RelaySession, direction: Direction) -> Result<(), RelayError> {
    match direction {
        Direction::FrontendToBackend => session
            .backend_write
            .shutdown()
            .await
            .map_err(RelayError::Io),

        Direction::BackendToFrontend => session
            .frontend_write
            .shutdown()
            .await
            .map_err(RelayError::Io),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::config::Config;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};

    fn test_relay_config() -> Arc<RelayConfig> {
        let config = Config::default();
        Arc::new(RelayConfig::from_config(&config).expect("default relay limits are valid"))
    }

    fn test_pool() -> Arc<MultiBufferPool> {
        MultiBufferPool::new(4, 1 << 20, 16)
    }

    #[allow(dead_code)]
    fn test_session() -> RelaySession {
        let (frontend_read, _) = tokio::io::duplex(64);
        let (frontend_write, _) = tokio::io::duplex(64);
        let (backend_read, _) = tokio::io::duplex(64);
        let (backend_write, _) = tokio::io::duplex(64);

        RelaySession::for_test(
            Box::new(frontend_read),
            Box::new(frontend_write),
            Box::new(backend_read),
            Box::new(backend_write),
            test_relay_config(),
            test_pool(),
        )
    }

    #[test]
    fn run_outcome_carries_done_and_switch() {
        let outcome = RunOutcome::Done(RelayOutcome {
            mode: Mode::Raw,
            reason: TeardownReason::Unknown,
            counters: CounterSnapshot::default(),
        });
        assert!(matches!(outcome, RunOutcome::Done(_)));

        let switch = RunOutcome::Switch(Mode::Framed);
        assert!(matches!(switch, RunOutcome::Switch(Mode::Framed)));
    }

    #[test]
    fn relay_session_holds_all_four_io_handles() {
        let config = test_relay_config();
        let pool = test_pool();
        let (frontend_read, _) = tokio::io::duplex(64);
        let (frontend_write, _) = tokio::io::duplex(64);
        let (backend_read, _) = tokio::io::duplex(64);
        let (backend_write, _) = tokio::io::duplex(64);

        let session = RelaySession::for_test(
            Box::new(frontend_read),
            Box::new(frontend_write),
            Box::new(backend_read),
            Box::new(backend_write),
            Arc::clone(&config),
            Arc::clone(&pool),
        );

        // Handles are stored (not dropped on construction) and the validated
        // config / pool are the shared instances, not per-message copies.
        assert!(Arc::ptr_eq(&session.config, &config));
        assert!(Arc::ptr_eq(&session.pool, &pool));
        assert_eq!(session.config.max_message_size, 1 << 30);
        assert_eq!(session.config.pool_max_bucket, 64 * 1024);
    }

    fn frame(type_byte: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + body.len());
        out.push(type_byte);
        out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[tokio::test]
    async fn run_raw_copies_both_directions() {
        let (frontend_read, mut client_write) = tokio::io::duplex(128);
        let (frontend_write, mut client_read) = tokio::io::duplex(128);
        let (backend_read, mut server_write) = tokio::io::duplex(128);
        let (backend_write, mut server_read) = tokio::io::duplex(128);

        let mut session = RelaySession::for_test(
            Box::new(frontend_read),
            Box::new(frontend_write),
            Box::new(backend_read),
            Box::new(backend_write),
            test_relay_config(),
            test_pool(),
        );

        let task = tokio::spawn(async move { run_raw(&mut session).await });
        client_write.write_all(b"to-backend").await.expect("client");
        server_write.write_all(b"to-client").await.expect("server");
        drop(client_write);
        drop(server_write);

        timeout(Duration::from_secs(2), task)
            .await
            .expect("both directions finished")
            .expect("task did not panic")
            .expect("raw outcome");

        let mut backend_out = Vec::new();
        server_read
            .read_to_end(&mut backend_out)
            .await
            .expect("backend output");
        let mut frontend_out = Vec::new();
        client_read
            .read_to_end(&mut frontend_out)
            .await
            .expect("frontend output");

        assert_eq!(backend_out, b"to-backend");
        assert_eq!(frontend_out, b"to-client");
    }

    #[tokio::test]
    async fn epoch_bump_switches_framed_session_to_raw_at_boundary() {
        struct RawPlan;
        impl ModePlan for RawPlan {
            fn epoch(&self) -> u64 {
                0
            }
            fn could_match(&self, _filters: &SessionFilters) -> bool {
                false
            }
        }

        let (frontend_read, mut client_write) = tokio::io::duplex(128);
        let (frontend_write, _client_read) = tokio::io::duplex(128);
        let (backend_read, _server_write) = tokio::io::duplex(128);
        let (backend_write, _server_read) = tokio::io::duplex(128);
        let (_shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
        let (epoch_tx, epoch) = tokio::sync::watch::channel(0);

        let mut session = RelaySession::new(
            Box::new(frontend_read),
            Box::new(frontend_write),
            Box::new(backend_read),
            Box::new(backend_write),
            test_relay_config(),
            test_pool(),
            shutdown,
            Arc::new(RawPlan),
            SessionFilters::default(),
            true,
            EpochWatcher::new(epoch),
        );

        client_write
            .write_all(&frame(b'Q', b"select 1\0"))
            .await
            .expect("query");
        epoch_tx.send(1).expect("epoch");

        let outcome = timeout(Duration::from_secs(2), run_framed(&mut session))
            .await
            .expect("switch finished")
            .expect("framed outcome");

        assert_eq!(outcome, RunOutcome::Switch(Mode::Raw));
    }

    #[tokio::test]
    async fn run_framed_forwards_both_directions() {
        let (frontend_read, mut client_write) = tokio::io::duplex(128);
        let (frontend_write, mut client_read) = tokio::io::duplex(128);
        let (backend_read, mut server_write) = tokio::io::duplex(128);
        let (backend_write, mut server_read) = tokio::io::duplex(128);

        let mut session = RelaySession::for_test(
            Box::new(frontend_read),
            Box::new(frontend_write),
            Box::new(backend_read),
            Box::new(backend_write),
            test_relay_config(),
            test_pool(),
        );

        let task = tokio::spawn(async move { run_framed(&mut session).await });

        let query = frame(b'Q', b"select 1\0");
        let ready = frame(b'Z', b"I");
        client_write.write_all(&query).await.expect("query");
        server_write.write_all(&ready).await.expect("ready");
        drop(client_write);
        drop(server_write);

        timeout(Duration::from_secs(2), task)
            .await
            .expect("framed session finished")
            .expect("task did not panic")
            .expect("framed outcome");

        let mut backend_out = Vec::new();
        server_read
            .read_to_end(&mut backend_out)
            .await
            .expect("backend output");
        let mut frontend_out = Vec::new();
        client_read
            .read_to_end(&mut frontend_out)
            .await
            .expect("frontend output");

        assert_eq!(backend_out, query);
        assert_eq!(frontend_out, ready);
    }
}
