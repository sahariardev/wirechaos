#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub(crate) enum Direction {
    FrontendToBackend,
    BackendToFrontend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum MessageKind {
    Query,
    Parse,
    Bind,
    Describe,
    Execute,
    Close,
    Sync,
    Flush,
    FunctionCall,
    RowDescription,
    DataRow,
    CommandComplete,
    ReadyForQuery,
    ErrorResponse,
    NoticeResponse,
    NotificationResponse,
    CopyInResponse,
    CopyOutResponse,
    CopyBothResponse,
    CopyData,
    CopyDone,
    CopyFail,
    ParameterStatus,
    BackendKeyData,
    EmptyQueryResponse,
    NoData,
    PortalSuspended,
    ParameterDescription,
    ParseComplete,
    BindComplete,
    CloseComplete,
    Terminate,
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct MessageInfo {
    pub(crate) direction: Direction,
    pub(crate) kind: MessageKind,
}

#[must_use]
#[allow(dead_code)]
pub(crate) fn classify(direction: Direction, type_byte: u8) -> MessageInfo {
    use Direction::{BackendToFrontend, FrontendToBackend};
    use MessageKind::{
        Bind, BindComplete, Close, CloseComplete, CommandComplete, CopyBothResponse, CopyData,
        CopyDone, CopyFail, CopyInResponse, CopyOutResponse, DataRow, Describe, EmptyQueryResponse,
        ErrorResponse, Execute, Flush, FunctionCall, NoData, NoticeResponse, NotificationResponse,
        ParameterDescription, ParameterStatus, Parse, ParseComplete, PortalSuspended, Query,
        ReadyForQuery, RowDescription, Sync, Terminate,
    };

    let kind = match (direction, type_byte) {
        // Frontend messages.
        (FrontendToBackend, b'B') => Bind,
        (FrontendToBackend, b'C') => Close,
        (FrontendToBackend, b'D') => Describe,
        (FrontendToBackend, b'E') => Execute,
        (FrontendToBackend, b'F') => FunctionCall,
        (FrontendToBackend, b'H') => Flush,
        (FrontendToBackend, b'P') => Parse,
        (FrontendToBackend, b'Q') => Query,
        (FrontendToBackend, b'S') => Sync,
        (FrontendToBackend, b'X') => Terminate,
        (FrontendToBackend, b'c') => CopyDone,
        (FrontendToBackend, b'd') => CopyData,
        (FrontendToBackend, b'f') => CopyFail,

        // Backend messages.
        (BackendToFrontend, b'1') => ParseComplete,
        (BackendToFrontend, b'2') => BindComplete,
        (BackendToFrontend, b'3') => CloseComplete,
        (BackendToFrontend, b'A') => NotificationResponse,
        (BackendToFrontend, b'C') => CommandComplete,
        (BackendToFrontend, b'D') => DataRow,
        (BackendToFrontend, b'E') => ErrorResponse,
        (BackendToFrontend, b'G') => CopyInResponse,
        (BackendToFrontend, b'H') => CopyOutResponse,
        (BackendToFrontend, b'I') => EmptyQueryResponse,
        (BackendToFrontend, b'K') => MessageKind::BackendKeyData,
        (BackendToFrontend, b'N') => NoticeResponse,
        (BackendToFrontend, b'S') => ParameterStatus,
        (BackendToFrontend, b'T') => RowDescription,
        (BackendToFrontend, b'W') => CopyBothResponse,
        (BackendToFrontend, b'Z') => ReadyForQuery,
        (BackendToFrontend, b'c') => CopyDone,
        (BackendToFrontend, b'd') => CopyData,
        (BackendToFrontend, b'f') => CopyFail,
        (BackendToFrontend, b'n') => NoData,
        (BackendToFrontend, b's') => PortalSuspended,
        (BackendToFrontend, b't') => ParameterDescription,

        _ => MessageKind::Opaque,
    };

    MessageInfo { direction, kind }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Phase {
    Startup,
    Auth,
    Query,
    Copy,
    Ready,
    Terminate,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct PhaseTracker {
    phase: Phase,
}

#[allow(dead_code)]
impl PhaseTracker {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            phase: Phase::Ready,
        }
    }

    #[must_use]
    pub(crate) fn phase(&self) -> Phase {
        self.phase
    }

    pub(crate) fn observe(&mut self, info: &MessageInfo) {
        use Direction::{BackendToFrontend, FrontendToBackend};
        use MessageKind::{
            Bind, BindComplete, Close, CloseComplete, CommandComplete, CopyBothResponse, CopyData,
            CopyDone, CopyFail, CopyInResponse, CopyOutResponse, DataRow, Describe,
            EmptyQueryResponse, ErrorResponse, Execute, Flush, FunctionCall, NoData,
            NoticeResponse, NotificationResponse, ParameterDescription, ParameterStatus, Parse,
            ParseComplete, PortalSuspended, Query, ReadyForQuery, RowDescription, Sync, Terminate,
        };
        use Phase::{Auth, Copy, Query as QueryPhase, Ready, Startup};

        self.phase = match (info.direction, info.kind) {
            (FrontendToBackend, Terminate) => Phase::Terminate,
            (BackendToFrontend, CopyInResponse | CopyOutResponse | CopyBothResponse) => Copy,
            (_, CopyData | CopyDone | CopyFail) => match self.phase {
                Copy => Copy,
                _ => self.phase,
            },

            (BackendToFrontend, ReadyForQuery) => Ready,
            (
                FrontendToBackend,
                Query | Parse | Bind | Describe | Execute | Close | Sync | Flush | FunctionCall,
            ) => QueryPhase,
            (
                BackendToFrontend,
                RowDescription | DataRow | CommandComplete | EmptyQueryResponse | NoData
                | PortalSuspended | ParameterDescription | ParseComplete | BindComplete
                | CloseComplete,
            ) => match self.phase {
                Copy => Copy,
                _ => QueryPhase,
            },

            (BackendToFrontend, ErrorResponse) => match self.phase {
                Startup | Auth | Copy => self.phase,
                _ => QueryPhase,
            },
            (BackendToFrontend, NoticeResponse | NotificationResponse) => self.phase,
            (BackendToFrontend, ParameterStatus | MessageKind::BackendKeyData) => {
                match self.phase {
                    Startup | Auth => Ready,
                    _ => self.phase,
                }
            }

            // Opaque and out-of-phase messages must not move the state machine.
            _ => self.phase,
        };
    }
}

impl Default for PhaseTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(direction: Direction, type_byte: u8) -> MessageInfo {
        classify(direction, type_byte)
    }

    #[test]
    fn classification_depends_on_direction() {
        use Direction::{BackendToFrontend, FrontendToBackend};
        use MessageKind::*;

        // Reused letters must never be classified by type byte alone.
        assert_eq!(info(FrontendToBackend, b'S').kind, Sync);
        assert_eq!(info(BackendToFrontend, b'S').kind, ParameterStatus);
        assert_eq!(info(FrontendToBackend, b'D').kind, Describe);
        assert_eq!(info(BackendToFrontend, b'D').kind, DataRow);
        assert_eq!(info(FrontendToBackend, b'C').kind, Close);
        assert_eq!(info(BackendToFrontend, b'C').kind, CommandComplete);
        assert_eq!(info(FrontendToBackend, b'E').kind, Execute);
        assert_eq!(info(BackendToFrontend, b'E').kind, ErrorResponse);
        assert_eq!(info(FrontendToBackend, b'H').kind, Flush);
        assert_eq!(info(BackendToFrontend, b'H').kind, CopyOutResponse);

        // Direction is preserved on every classification.
        assert_eq!(info(FrontendToBackend, b'Q').direction, FrontendToBackend);
        assert_eq!(info(BackendToFrontend, b'Z').direction, BackendToFrontend);
    }

    #[test]
    fn known_messages_are_classified() {
        use Direction::{BackendToFrontend, FrontendToBackend};
        use MessageKind::*;

        let frontend = [
            (b'B', Bind),
            (b'C', Close),
            (b'D', Describe),
            (b'E', Execute),
            (b'F', FunctionCall),
            (b'H', Flush),
            (b'P', Parse),
            (b'Q', Query),
            (b'S', Sync),
            (b'X', Terminate),
            (b'c', CopyDone),
            (b'd', CopyData),
            (b'f', CopyFail),
        ];
        for (type_byte, kind) in frontend {
            assert_eq!(info(FrontendToBackend, type_byte).kind, kind);
        }

        let backend = [
            (b'1', ParseComplete),
            (b'2', BindComplete),
            (b'3', CloseComplete),
            (b'A', NotificationResponse),
            (b'C', CommandComplete),
            (b'D', DataRow),
            (b'E', ErrorResponse),
            (b'G', CopyInResponse),
            (b'H', CopyOutResponse),
            (b'I', EmptyQueryResponse),
            (b'K', BackendKeyData),
            (b'N', NoticeResponse),
            (b'S', ParameterStatus),
            (b'T', RowDescription),
            (b'W', CopyBothResponse),
            (b'Z', ReadyForQuery),
            (b'c', CopyDone),
            (b'd', CopyData),
            (b'f', CopyFail),
            (b'n', NoData),
            (b's', PortalSuspended),
            (b't', ParameterDescription),
        ];
        for (type_byte, kind) in backend {
            assert_eq!(info(BackendToFrontend, type_byte).kind, kind);
        }
    }

    #[test]
    fn unknown_type_is_opaque_and_forwardable() {
        use Direction::{BackendToFrontend, FrontendToBackend};

        assert_eq!(info(FrontendToBackend, b'\x7f').kind, MessageKind::Opaque);
        assert_eq!(info(BackendToFrontend, b'\x7f').kind, MessageKind::Opaque);
        assert_eq!(
            info(FrontendToBackend, b'p').kind,
            MessageKind::Opaque,
            "auth-only frontend messages are outside the relay's phase machine"
        );
    }

    #[test]
    fn notices_do_not_end_a_response() {
        use Direction::{BackendToFrontend, FrontendToBackend};

        let mut tracker = PhaseTracker::new();
        tracker.observe(&info(FrontendToBackend, b'Q'));
        assert_eq!(tracker.phase(), Phase::Query);

        tracker.observe(&info(BackendToFrontend, b'N'));
        tracker.observe(&info(BackendToFrontend, b'A'));
        assert_eq!(tracker.phase(), Phase::Query);

        tracker.observe(&info(BackendToFrontend, b'D'));
        tracker.observe(&info(BackendToFrontend, b'C'));
        assert_eq!(tracker.phase(), Phase::Query);
    }

    #[test]
    fn phase_moves_from_query_to_copy_to_ready() {
        use Direction::{BackendToFrontend, FrontendToBackend};

        let mut tracker = PhaseTracker::new();
        assert_eq!(tracker.phase(), Phase::Ready);

        tracker.observe(&info(FrontendToBackend, b'Q'));
        assert_eq!(tracker.phase(), Phase::Query);

        tracker.observe(&info(BackendToFrontend, b'H'));
        assert_eq!(tracker.phase(), Phase::Copy);

        tracker.observe(&info(BackendToFrontend, b'd'));
        assert_eq!(tracker.phase(), Phase::Copy);

        tracker.observe(&info(BackendToFrontend, b'c'));
        assert_eq!(tracker.phase(), Phase::Copy);

        tracker.observe(&info(BackendToFrontend, b'Z'));
        assert_eq!(tracker.phase(), Phase::Ready);
    }

    #[test]
    fn ready_for_query_ends_copy_in_either_direction() {
        use Direction::{BackendToFrontend, FrontendToBackend};

        let mut tracker = PhaseTracker::new();
        tracker.observe(&info(FrontendToBackend, b'Q'));
        tracker.observe(&info(BackendToFrontend, b'G'));
        assert_eq!(tracker.phase(), Phase::Copy);

        tracker.observe(&info(FrontendToBackend, b'd'));
        assert_eq!(tracker.phase(), Phase::Copy);

        tracker.observe(&info(BackendToFrontend, b'Z'));
        assert_eq!(tracker.phase(), Phase::Ready);
    }

    #[test]
    fn terminate_enters_terminate_phase() {
        use Direction::FrontendToBackend;

        let mut tracker = PhaseTracker::new();
        tracker.observe(&info(FrontendToBackend, b'X'));
        assert_eq!(tracker.phase(), Phase::Terminate);
    }

    #[test]
    fn opaque_messages_do_not_move_the_phase() {
        use Direction::{BackendToFrontend, FrontendToBackend};

        let mut tracker = PhaseTracker::new();
        tracker.observe(&info(FrontendToBackend, b'Q'));
        assert_eq!(tracker.phase(), Phase::Query);

        tracker.observe(&info(FrontendToBackend, b'\x7f'));
        tracker.observe(&info(BackendToFrontend, b'\x7f'));
        assert_eq!(tracker.phase(), Phase::Query);
    }
}
