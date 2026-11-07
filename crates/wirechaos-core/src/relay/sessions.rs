use crate::proxy::buffer_pool::MultiBufferPool;
use crate::relay::config::RelayConfig;
use crate::relay::error::{RelayError, TeardownReason};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Mode {
    Raw,
    Framed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code
)]
pub(crate) struct RelayOutcome {
    pub(crate) mode: Mode,
    pub(crate) reason: TeardownReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code
)]
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
}

impl RelaySession {
    #[allow(
        dead_code
    )]
    pub(crate) fn new(
        frontend_read: Box<dyn AsyncRead + Send + Unpin>,
        frontend_write: Box<dyn AsyncWrite + Send + Unpin>,
        backend_read: Box<dyn AsyncRead + Send + Unpin>,
        backend_write: Box<dyn AsyncWrite + Send + Unpin>,
        config: Arc<RelayConfig>,
        pool: Arc<MultiBufferPool>,
    ) -> Self {
        Self {
            frontend_read,
            frontend_write,
            backend_read,
            backend_write,
            config,
            pool,
        }
    }
}

#[allow(
    dead_code
)]
pub(crate) async fn run(session: RelaySession) -> Result<RelayOutcome, RelayError> {
    let _ = session;
    Err(RelayError::NotImplemented {
        task: "6.1",
        what: "relay::run",
    })
}

#[allow(dead_code)]
pub(crate) async fn run_raw(session: &mut RelaySession) -> Result<RunOutcome, RelayError> {
    let _ = session;
    Err(RelayError::NotImplemented {
        task: "run_raw",
        what: "relay::run_raw",
    })
}

#[allow(dead_code)]
pub(crate) async fn run_framed(session: &mut RelaySession) -> Result<RunOutcome, RelayError> {
    let _ = session;
    Err(RelayError::NotImplemented {
        task: "run_framed",
        what: "relay::run_framed",
    })
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
