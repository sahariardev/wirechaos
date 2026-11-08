use crate::relay::classification::{Direction, MessageInfo, MessageKind, PhaseTracker};
use crate::relay::error::RelayError;
use crate::relay::reader::{Frame, FrameBody};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum TxnStatus {
    Idle,
    InTransaction,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum CopyMode {
    None,
    In,
    Out,
    Both,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct SessionState {
    pub(crate) txn: TxnStatus,
    pub(crate) copy: CopyMode,
    pub(crate) phase: PhaseTracker,
}

impl SessionState {
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            txn: TxnStatus::Idle,
            copy: CopyMode::None,
            phase: PhaseTracker::new(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn observe(&mut self, info: &MessageInfo, frame: &Frame) -> Result<(), RelayError> {
        self.phase.observe(info);

        match (info.kind, info.direction) {
            (MessageKind::ReadyForQuery, Direction::BackendToFrontend) => {
                let body = body_bytes(frame);
                if body.len() != 1 {
                    return Err(RelayError::Protocol {
                        code: "08P01",
                        message: "invalid ReadyForQuery body".to_owned(),
                    });
                }
                self.txn = match body[0] {
                    b'I' => TxnStatus::Idle,
                    b'T' => TxnStatus::InTransaction,
                    b'E' => TxnStatus::Failed,
                    _ => {
                        return Err(RelayError::Protocol {
                            code: "08P01",
                            message: "invalid ReadyForQuery status".to_owned(),
                        });
                    }
                };
                self.copy = CopyMode::None;
            }
            (MessageKind::CopyInResponse, Direction::BackendToFrontend) => {
                self.copy = CopyMode::In;
            }
            (MessageKind::CopyOutResponse, Direction::BackendToFrontend) => {
                self.copy = CopyMode::Out;
            }
            (MessageKind::CopyBothResponse, Direction::BackendToFrontend) => {
                self.copy = CopyMode::Both;
            }
            (MessageKind::CopyFail, _) => {
                self.copy = CopyMode::None;
            }
            (MessageKind::CopyData, _) if self.copy == CopyMode::None => {}
            _ => {}
        }

        Ok(())
    }
}

impl Default for SessionState {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
fn body_bytes(frame: &Frame) -> &[u8] {
    match &frame.body {
        FrameBody::Empty => &[],
        FrameBody::Pooled(b) => b.as_slice(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::buffer_pool::MultiBufferPool;
    use crate::relay::classification::classify;
    use crate::relay::header::FrameHeader;
    use std::sync::Arc;

    fn frame(type_byte: u8, body: &[u8]) -> Frame {
        if body.is_empty() {
            return Frame {
                header: FrameHeader {
                    type_byte,
                    body_len: 0,
                },
                body: FrameBody::Empty,
            };
        }
        let pool = Arc::new(MultiBufferPool::new(4, 64, 1));
        let mut buf = pool.get(body.len());
        buf.copy_from_slice(body);
        Frame {
            header: FrameHeader {
                type_byte,
                body_len: body.len(),
            },
            body: FrameBody::Pooled(buf),
        }
    }

    fn observe_msg(
        state: &mut SessionState,
        direction: Direction,
        type_byte: u8,
        body: &[u8],
    ) -> Result<(), RelayError> {
        let info = classify(direction, type_byte);
        state.observe(&info, &frame(type_byte, body))
    }

    #[test]
    fn transaction_status_is_tracked_from_ready_for_query() {
        let mut s = SessionState::new();
        observe_msg(&mut s, Direction::BackendToFrontend, b'Z', b"I").unwrap();
        assert_eq!(s.txn, TxnStatus::Idle);
        observe_msg(&mut s, Direction::BackendToFrontend, b'Z', b"T").unwrap();
        assert_eq!(s.txn, TxnStatus::InTransaction);
        observe_msg(&mut s, Direction::BackendToFrontend, b'Z', b"E").unwrap();
        assert_eq!(s.txn, TxnStatus::Failed);
    }

    #[test]
    fn notices_and_data_rows_do_not_change_transaction_status() {
        let mut s = SessionState::new();
        observe_msg(&mut s, Direction::BackendToFrontend, b'Z', b"T").unwrap();
        observe_msg(&mut s, Direction::BackendToFrontend, b'N', b"notice\0").unwrap();
        observe_msg(&mut s, Direction::BackendToFrontend, b'D', b"payload").unwrap();
        observe_msg(&mut s, Direction::BackendToFrontend, b'T', b"rows").unwrap();
        observe_msg(&mut s, Direction::BackendToFrontend, b'C', b"SELECT 1\0").unwrap();
        assert_eq!(s.txn, TxnStatus::InTransaction);
    }

    #[test]
    fn failed_transaction_recovers_to_idle() {
        let mut s = SessionState::new();
        observe_msg(&mut s, Direction::BackendToFrontend, b'Z', b"T").unwrap();
        observe_msg(&mut s, Direction::BackendToFrontend, b'Z', b"E").unwrap();
        assert_eq!(s.txn, TxnStatus::Failed);
        observe_msg(&mut s, Direction::BackendToFrontend, b'Z', b"I").unwrap();
        assert_eq!(s.txn, TxnStatus::Idle);
    }

    #[test]
    fn copy_mode_is_entered_and_left_correctly() {
        let mut s = SessionState::new();
        observe_msg(&mut s, Direction::BackendToFrontend, b'G', b"\0\0\0\0").unwrap();
        assert_eq!(s.copy, CopyMode::In);
        observe_msg(&mut s, Direction::BackendToFrontend, b'Z', b"I").unwrap();
        assert_eq!(s.copy, CopyMode::None);

        observe_msg(&mut s, Direction::BackendToFrontend, b'H', b"\0\0\0\0").unwrap();
        assert_eq!(s.copy, CopyMode::Out);
        observe_msg(&mut s, Direction::BackendToFrontend, b'c', b"").unwrap();
        observe_msg(&mut s, Direction::BackendToFrontend, b'Z', b"I").unwrap();
        assert_eq!(s.copy, CopyMode::None);
    }

    #[test]
    fn copy_both_is_tracked() {
        let mut s = SessionState::new();
        observe_msg(&mut s, Direction::BackendToFrontend, b'W', b"\0\0\0\0").unwrap();
        assert_eq!(s.copy, CopyMode::Both);
        observe_msg(&mut s, Direction::BackendToFrontend, b'Z', b"I").unwrap();
        assert_eq!(s.copy, CopyMode::None);
    }

    #[test]
    fn copy_fail_ends_copy() {
        let mut s = SessionState::new();
        observe_msg(&mut s, Direction::BackendToFrontend, b'G', b"\0\0\0\0").unwrap();
        assert_eq!(s.copy, CopyMode::In);
        observe_msg(&mut s, Direction::FrontendToBackend, b'f', b"fail\0").unwrap();
        assert_eq!(s.copy, CopyMode::None);
        observe_msg(&mut s, Direction::BackendToFrontend, b'Z', b"I").unwrap();
        assert_eq!(s.copy, CopyMode::None);
    }

    #[test]
    fn short_ready_for_query_body_is_a_protocol_error() {
        let mut s = SessionState::new();
        let err = observe_msg(&mut s, Direction::BackendToFrontend, b'Z', b"")
            .expect_err("empty Z body must be 08P01");
        assert_eq!(err.sqlstate(), Some("08P01"));
        let err = observe_msg(&mut s, Direction::BackendToFrontend, b'Z', b"IT")
            .expect_err("long Z body must be 08P01");
        assert_eq!(err.sqlstate(), Some("08P01"));
        let err = observe_msg(&mut s, Direction::BackendToFrontend, b'Z', b"X")
            .expect_err("unknown Z status must be 08P01");
        assert_eq!(err.sqlstate(), Some("08P01"));
    }

    #[test]
    fn copy_data_outside_copy_mode_is_flagged() {
        let mut s = SessionState::new();
        assert_eq!(s.copy, CopyMode::None);
        observe_msg(&mut s, Direction::FrontendToBackend, b'd', b"data").unwrap();
        assert_eq!(s.copy, CopyMode::None);
    }
}
