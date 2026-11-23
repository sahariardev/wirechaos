use crate::relay::capture::CapturedQuery;
use crate::relay::classification::{Direction, MessageInfo, Phase};
use crate::relay::degrade::BodyAccess;
use crate::relay::reader::Frame;
use crate::relay::state::{CopyMode, TxnStatus};
use crate::relay::{Mode, RelayError};
use std::time::Duration;

pub(crate) struct FrameContext<'a> {
    pub(crate) direction: Direction,
    pub(crate) info: MessageInfo,
    pub(crate) mode: Mode,
    pub(crate) phase: Phase,
    pub(crate) txn: TxnStatus,
    pub(crate) copy: CopyMode,
    pub(crate) pending: u32,
    pub(crate) body_access: BodyAccess,
    pub(crate) last_query: Option<&'a CapturedQuery>,
}

#[allow(dead_code)]
pub(crate) enum HookDecision {
    Pass,
    Forward { delay: Option<Duration> },
    Emit { frames: Vec<Frame> },
    SuppressResponse,
    Drop,
    Terminate,
}

pub(crate) trait RelayHooks: Send {
    fn on_frame(
        &mut self,
        ctx: &FrameContext<'_>,
        frame: &Frame,
    ) -> Result<HookDecision, RelayError>;
}

pub(crate) struct NoopHooks;

impl RelayHooks for NoopHooks {
    fn on_frame(
        &mut self,
        _ctx: &FrameContext<'_>,
        _frame: &Frame,
    ) -> Result<HookDecision, RelayError> {
        Ok(HookDecision::Pass)
    }
}
