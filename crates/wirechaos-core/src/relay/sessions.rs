use crate::proxy::buffer_pool::MultiBufferPool;
use crate::relay::config::RelayConfig;
use crate::relay::error::{RelayError, TearDownReason};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) enum Mode {
    Raw,
    Framed,
}

pub(crate) struct RelayOutcome {
    pub mode: Mode,
    pub reason: TearDownReason,
}

pub(crate) enum RunOutcome {
    Done(RelayOutcome),
    Switch(Mode),
}

pub(crate) struct RelaySession {
    pub(crate) frontend_reader: Box<dyn AsyncRead + Send + Unpin>,
    pub(crate) frontend_writer: Box<dyn AsyncWrite + Send + Unpin>,
    pub(crate) backend_reader: Box<dyn AsyncRead + Send + Unpin>,
    pub(crate) backend_writer: Box<dyn AsyncWrite + Send + Unpin>,
    pub(crate) config: RelayConfig,
    pub(crate) pool: Arc<MultiBufferPool>,
}

impl RelaySession {
    pub(crate) fn new(
        frontend_reader: Box<dyn AsyncRead + Send + Unpin>,
        frontend_writer: Box<dyn AsyncWrite + Send + Unpin>,
        backend_reader: Box<dyn AsyncRead + Send + Unpin>,
        backend_writer: Box<dyn AsyncWrite + Send + Unpin>,
        config: RelayConfig,
        pool: Arc<MultiBufferPool>,
    ) -> Self {
        todo!("Implement this")
    }

    pub(crate) fn run(sessions: RelaySession) -> Result<RelayOutcome, RelayError> {
        todo!("Implement this")
    }

    pub(crate) fn run_frame(sessions: &mut RelaySession) -> Result<RunOutcome, RelayError> {
        todo!("Implement this")
    }

    pub(crate) fn run_raw(sessions: &mut RelaySession) -> Result<RunOutcome, RelayError> {
        todo!("Implement this")
    }
}
