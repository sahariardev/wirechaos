#![allow(dead_code)]
use crate::relay::error::RelayError;
use crate::relay::hook::{FrameContext, HookDecision, RelayHooks};
use crate::relay::reader::Frame;
use std::time::Duration;

pub(crate) struct EngineDecision {
    pub(crate) action: EngineAction,
    pub(crate) notes: Vec<DecisionNote>,
}

#[derive(Default)]
pub(crate) enum EngineAction {
    #[default]
    PassThrough,
    Forward {
        delay: Option<Duration>,
    },
    Emit {
        frames: Vec<Frame>,
    },
    SuppressResponse,
}

#[derive(Debug)]
pub(crate) struct DecisionNote {
    pub(crate) message: String,
    pub(crate) degraded: bool,
}

pub(crate) trait ProtocolEngine: Send {
    fn needs_decode(&self) -> bool;

    fn on_frame(
        &mut self,
        ctx: &FrameContext<'_>,
        frame: &Frame,
    ) -> Result<EngineDecision, RelayError>;
}

pub(crate) struct EngineHooks {
    engine: Box<dyn ProtocolEngine>,
}

impl EngineHooks {
    pub(crate) fn new(engine: Box<dyn ProtocolEngine>) -> Self {
        Self { engine }
    }
}

impl RelayHooks for EngineHooks {
    fn on_frame(
        &mut self,
        ctx: &FrameContext<'_>,
        frame: &Frame,
    ) -> Result<HookDecision, RelayError> {
        if !self.engine.needs_decode() {
            return Ok(HookDecision::Pass);
        }

        let decision = self.engine.on_frame(ctx, frame)?;
        let _notes = decision.notes;

        Ok(match decision.action {
            EngineAction::PassThrough => HookDecision::Pass,
            EngineAction::Forward { delay } => HookDecision::Forward { delay },
            EngineAction::Emit { frames } => HookDecision::Emit { frames },
            EngineAction::SuppressResponse => HookDecision::SuppressResponse,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::capture::CapturedQuery;
    use crate::relay::classification::{classify, Direction, Phase};
    use crate::relay::degrade::BodyAccess;
    use crate::relay::header::FrameHeader;
    use crate::relay::reader::FrameBody;
    use crate::relay::sessions::Mode;
    use crate::relay::state::{CopyMode, TxnStatus};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct TestEngine {
        needs_decode: bool,
        calls: Arc<AtomicUsize>,
        action: EngineAction,
    }

    impl ProtocolEngine for TestEngine {
        fn needs_decode(&self) -> bool {
            self.needs_decode
        }

        fn on_frame(
            &mut self,
            _ctx: &FrameContext<'_>,
            _frame: &Frame,
        ) -> Result<EngineDecision, RelayError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(EngineDecision {
                action: std::mem::replace(&mut self.action, EngineAction::PassThrough),
                notes: Vec::new(),
            })
        }
    }

    fn ctx() -> FrameContext<'static> {
        FrameContext {
            direction: Direction::FrontendToBackend,
            info: classify(Direction::FrontendToBackend, b'Q'),
            mode: Mode::Framed,
            phase: Phase::Query,
            txn: TxnStatus::Idle,
            copy: CopyMode::None,
            pending: 1,
            body_access: BodyAccess::Complete,
            last_query: None::<&CapturedQuery>,
        }
    }

    fn frame() -> Frame {
        Frame {
            header: FrameHeader {
                type_byte: b'Q',
                body_len: 1,
            },
            body: FrameBody::Empty,
        }
    }

    #[test]
    fn empty_needs_never_decode_the_payload() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hooks = EngineHooks::new(Box::new(TestEngine {
            needs_decode: false,
            calls: Arc::clone(&calls),
            action: EngineAction::PassThrough,
        }));
        let decision = hooks.on_frame(&ctx(), &frame()).expect("decision");
        assert!(matches!(decision, HookDecision::Pass));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn engine_decision_maps_to_hook_decision() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut hooks = EngineHooks::new(Box::new(TestEngine {
            needs_decode: true,
            calls: Arc::clone(&calls),
            action: EngineAction::Forward {
                delay: Some(Duration::from_millis(1)),
            },
        }));
        let decision = hooks.on_frame(&ctx(), &frame()).expect("decision");
        assert!(matches!(decision, HookDecision::Forward { .. }));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}
