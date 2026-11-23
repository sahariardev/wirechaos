#![allow(dead_code)]
use crate::relay::hook::FrameContext;
use crate::relay::reader::Frame;
use tracing::{enabled, Level, Span};

/// Per-message debug span, or `None` at the default log level.
///
/// The gate is evaluated before any field is formatted or allocated. This is
/// the only per-message observability hook on the hot path.
pub(crate) fn message_span(ctx: &FrameContext<'_>, frame: &Frame) -> Option<Span> {
    if !enabled!(Level::DEBUG) {
        return None;
    }

    Some(tracing::debug_span!(
        "relay_frame",
        direction = ?ctx.direction,
        kind = ?ctx.info.kind,
        phase = ?ctx.phase,
        mode = ?ctx.mode,
        bytes = 5 + frame.header.body_len,
        body_access = ?ctx.body_access,
        pending = ctx.pending,
        txn = ?ctx.txn,
        copy = ?ctx.copy,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::capture::CapturedQuery;
    use crate::relay::classification::{classify, Direction};
    use crate::relay::degrade::BodyAccess;
    use crate::relay::header::FrameHeader;
    use crate::relay::reader::FrameBody;
    use crate::relay::sessions::Mode;
    use crate::relay::state::{CopyMode, TxnStatus};

    #[test]
    fn default_level_does_not_create_a_span() {
        let info = classify(Direction::FrontendToBackend, b'Q');
        let ctx = FrameContext {
            direction: Direction::FrontendToBackend,
            info,
            mode: Mode::Framed,
            phase: crate::relay::classification::Phase::Query,
            txn: TxnStatus::Idle,
            copy: CopyMode::None,
            pending: 1,
            body_access: BodyAccess::Complete,
            last_query: None::<&CapturedQuery>,
        };
        let frame = Frame {
            header: FrameHeader {
                type_byte: b'Q',
                body_len: 8,
            },
            body: FrameBody::Empty,
        };
        assert!(message_span(&ctx, &frame).is_none());
    }
}
