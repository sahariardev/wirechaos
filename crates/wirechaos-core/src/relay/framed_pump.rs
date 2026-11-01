use crate::relay::classification::Direction;
use crate::relay::error::{RelayError, TearDownReason};
use crate::relay::sessions::RelaySession;

pub(crate) enum PumpOutcome {
    Continue,
    Stop(TearDownReason),
}

impl RelaySession {
    pub(crate) fn pump_one(&self, direction: Direction) -> Result<PumpOutcome, RelayError> {
        todo!("Implement this")
    }
}
