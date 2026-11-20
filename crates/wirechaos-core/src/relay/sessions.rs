use crate::proxy::buffer_pool::MultiBufferPool;
use crate::relay::classification::Direction;
use crate::relay::config::RelayConfig;
use crate::relay::error::{RelayError, TeardownReason};
use crate::relay::raw_pump::{copy_direction, RawStop, ShutdownSignal};
use crate::relay::reader::{FrameRead, FrameReader};
use crate::relay::state::SessionState;
use crate::relay::writer::FrameWriter;
use crate::relay::PumpOutcome;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Mode {
    Raw,
    Framed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct RelayOutcome {
    pub(crate) mode: Mode,
    pub(crate) reason: TeardownReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
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

    pub(crate) shutdown: ShutdownSignal,
}

impl RelaySession {
    #[allow(dead_code)]
    pub(crate) fn new(
        frontend_read: Box<dyn AsyncRead + Send + Unpin>,
        frontend_write: Box<dyn AsyncWrite + Send + Unpin>,
        backend_read: Box<dyn AsyncRead + Send + Unpin>,
        backend_write: Box<dyn AsyncWrite + Send + Unpin>,
        config: Arc<RelayConfig>,
        pool: Arc<MultiBufferPool>,
        shutdown: ShutdownSignal,
    ) -> Self {
        let max_message_size = config.max_message_size;
        let pool_max_bucket = config.pool_max_bucket;
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
        }
    }
}

#[allow(dead_code)]
pub(crate) async fn run(session: RelaySession) -> Result<RelayOutcome, RelayError> {
    let _ = session;
    Err(RelayError::NotImplemented {
        task: "6.1",
        what: "relay::run",
    })
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
        (RawStop::Eof, RawStop::Eof) => TeardownReason::Unknown,
    };

    Ok(RunOutcome::Done(RelayOutcome {
        mode: Mode::Raw,
        reason,
    }))
}

#[allow(dead_code)]
pub(crate) async fn run_framed(session: &mut RelaySession) -> Result<RunOutcome, RelayError> {
    loop {
        let selected = tokio::select! {
          changed = session.shutdown.changed() => {
                let _ = changed;
                return Ok(RunOutcome::Done(RelayOutcome {
                    mode: Mode::Framed,
                    reason: TeardownReason::Unknown
                }))
            }

            result = session.frontend_reader.next_frame(&mut session.frontend_read) => {
                (Direction::FrontendToBackend, result?)
            }

            result = session.backend_reader.next_frame(&mut session.backend_read) => {
                (Direction::FrontendToBackend, result?)
            }
        };

        let (direction, frame) = selected;

        match frame {
            None => {
                half_close(session, direction).await?;

                return Ok(RunOutcome::Done(RelayOutcome {
                    mode: Mode::Framed,
                    reason: TeardownReason::Unknown,
                }));
            }
            Some(FrameRead::Complete(frame)) => {
                if let PumpOutcome::Stop(reason) = session.forward_one(direction, frame).await? {
                    return Ok(RunOutcome::Done(RelayOutcome {
                        mode: Mode::Framed,
                        reason,
                    }));
                }
            }

            Some(FrameRead::Stream(header)) => {
                return Err(RelayError::NotImplemented {
                    task: "run_framed",
                    what: "relay::run_framed",
                });
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

    fn test_relay_config() -> Arc<RelayConfig> {
        let config = Config::default();
        Arc::new(RelayConfig::from_config(&config).expect("default relay limits are valid"))
    }

    fn test_pool() -> Arc<MultiBufferPool> {
        MultiBufferPool::new(4, 1 << 20, 16)
    }

    fn test_session() -> RelaySession {
        let (frontend_read, _) = tokio::io::duplex(64);
        let (frontend_write, _) = tokio::io::duplex(64);
        let (backend_read, _) = tokio::io::duplex(64);
        let (backend_write, _) = tokio::io::duplex(64);

        RelaySession::new(
            Box::new(frontend_read),
            Box::new(frontend_write),
            Box::new(backend_read),
            Box::new(backend_write),
            test_relay_config(),
            test_pool(),
        )
    }

    #[tokio::test]
    async fn placeholder_run_returns_not_implemented() {
        let session = test_session();
        let err = run(session).await.expect_err("6.1 placeholder");

        assert!(matches!(
            err,
            RelayError::NotImplemented {
                task: "6.1",
                what: "relay::run"
            }
        ));
    }

    #[tokio::test]
    async fn placeholder_run_raw_returns_not_implemented() {
        let mut session = test_session();
        let err = run_raw(&mut session).await.expect_err("6.1 placeholder");

        assert!(matches!(
            err,
            RelayError::NotImplemented {
                task: "run_raw",
                what: "relay::run_raw"
            }
        ));
    }

    #[tokio::test]
    async fn placeholder_run_framed_returns_not_implemented() {
        let mut session = test_session();
        let err = run_framed(&mut session).await.expect_err("6.1 placeholder");

        assert!(matches!(
            err,
            RelayError::NotImplemented {
                task: "run_framed",
                what: "relay::run_framed"
            }
        ));
    }

    #[test]
    fn run_outcome_carries_done_and_switch() {
        let outcome = RunOutcome::Done(RelayOutcome {
            mode: Mode::Raw,
            reason: TeardownReason::Unknown,
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

        let session = RelaySession::new(
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
}
