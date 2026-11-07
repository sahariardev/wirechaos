use crate::relay::classification::Direction;
use crate::relay::error::{RelayError, TeardownReason};
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
        let _ = (self, direction);
        Err(RelayError::NotImplemented {
            task: "pump_one",
            what: "RelaySession::pump_one",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::config::Config;

    fn test_session() -> RelaySession {
        let (frontend_read, _) = tokio::io::duplex(64);
        let (frontend_write, _) = tokio::io::duplex(64);
        let (backend_read, _) = tokio::io::duplex(64);
        let (backend_write, _) = tokio::io::duplex(64);
        let config = Config::default();
        let relay_config = Arc::new(
            crate::relay::RelayConfig::from_config(&config)
                .expect("default relay limits are valid"),
        );

        RelaySession::new(
            Box::new(frontend_read),
            Box::new(frontend_write),
            Box::new(backend_read),
            Box::new(backend_write),
            relay_config,
            crate::proxy::buffer_pool::MultiBufferPool::new(4, 1 << 20, 16),
        )
    }

    use std::sync::Arc;

    #[tokio::test]
    async fn placeholder_pump_one_returns_not_implemented() {
        let mut session = test_session();
        let err = session
            .pump_one(Direction::FrontendToBackend)
            .await
            .expect_err("6.1 placeholder");

        assert!(matches!(
            err,
            RelayError::NotImplemented {
                task: "pump_one",
                what: "RelaySession::pump_one"
            }
        ));
    }
}
