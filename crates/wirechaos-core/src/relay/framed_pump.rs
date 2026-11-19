use crate::relay::classification::Direction;
use crate::relay::classification::Direction::BackendToFrontend;
use crate::relay::error::{RelayError, TeardownReason};
use crate::relay::reader::FrameRead;
use crate::relay::sessions::RelaySession;
use tokio::io::AsyncReadExt;

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
        let mut reader = &mut self.frontend_read;
        let mut writer = &mut self.backend_write;

        if direction == BackendToFrontend {
            let mut reader = &mut self.backend_read;
            let mut writer = &mut self.frontend_write;
        }

        let frame = self.frame_reader.next_frame(&mut reader).await?;

        match frame {
            Some(frame_read) => match frame_read {
                FrameRead::Complete(f) => {
                    self.frame_writer.write_frame(&mut writer, &f).await?;
                }
                FrameRead::Stream(header) => {
                    let buffer = self.pool.get(self.config.pool_max_bucket);

                    self.frame_writer
                        .write_streamed(&mut writer, &mut reader, &header, buffer)
                        .await?;
                }
            },
            None => {}
        }

        Ok(PumpOutcome::Continue)
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
