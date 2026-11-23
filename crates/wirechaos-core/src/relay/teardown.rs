use crate::relay::error::{fatal_error_response, RelayError, TeardownReason};
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TeardownTrigger {
    ClientTerminate,
    ClientEof,
    ClientReset,
    BackendEof { response_pending: bool },
    FramingViolation,
    ChaosTerminate { send_error: bool, orderly: bool },
    AdminKill,
    IdleTimeout,
    Panic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientAction {
    Close,
    HalfCloseThenClose,
    Fatal {
        code: &'static str,
        message: &'static str,
    },
    NoticeThenFatal {
        code: &'static str,
        message: &'static str,
    },
    OptionalFatal {
        code: &'static str,
        message: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendAction {
    Close,
    ShutdownWrite,
    ForwardTerminateThenClose,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TeardownDecision {
    pub(crate) client: ClientAction,
    pub(crate) backend: BackendAction,
    pub(crate) reason: TeardownReason,
}

pub(crate) fn decide_teardown(trigger: TeardownTrigger) -> TeardownDecision {
    match trigger {
        TeardownTrigger::ClientTerminate => TeardownDecision {
            client: ClientAction::Close,
            backend: BackendAction::ForwardTerminateThenClose,
            reason: TeardownReason::ClientTerminate,
        },
        TeardownTrigger::ClientEof => TeardownDecision {
            client: ClientAction::HalfCloseThenClose,
            backend: BackendAction::ShutdownWrite,
            reason: TeardownReason::ClientEof,
        },
        TeardownTrigger::ClientReset => TeardownDecision {
            client: ClientAction::Close,
            backend: BackendAction::Close,
            reason: TeardownReason::ClientReset,
        },
        TeardownTrigger::BackendEof {
            response_pending: true,
        } => TeardownDecision {
            client: ClientAction::Fatal {
                code: "57P01",
                message: "server closed the connection unexpectedly",
            },
            backend: BackendAction::None,
            reason: TeardownReason::BackendEofWhileWaiting,
        },
        TeardownTrigger::BackendEof {
            response_pending: false,
        } => TeardownDecision {
            client: ClientAction::Close,
            backend: BackendAction::None,
            reason: TeardownReason::BackendEof,
        },
        TeardownTrigger::FramingViolation => TeardownDecision {
            client: ClientAction::Fatal {
                code: "08P01",
                message: "invalid message length",
            },
            backend: BackendAction::Close,
            reason: TeardownReason::FramingViolation,
        },
        TeardownTrigger::ChaosTerminate {
            send_error,
            orderly,
        } => TeardownDecision {
            client: if send_error {
                ClientAction::OptionalFatal {
                    code: "57P01",
                    message: "session terminated by chaos rule",
                }
            } else {
                ClientAction::Close
            },
            backend: if orderly {
                BackendAction::ForwardTerminateThenClose
            } else {
                BackendAction::Close
            },
            reason: TeardownReason::ChaosTerminate,
        },
        TeardownTrigger::AdminKill => TeardownDecision {
            client: ClientAction::Fatal {
                code: "57P01",
                message: "session terminated by administrator",
            },
            backend: BackendAction::Close,
            reason: TeardownReason::AdminKill,
        },
        TeardownTrigger::IdleTimeout => TeardownDecision {
            client: ClientAction::NoticeThenFatal {
                code: "57P01",
                message: "session idle timeout",
            },
            backend: BackendAction::Close,
            reason: TeardownReason::IdleTimeout,
        },
        TeardownTrigger::Panic => TeardownDecision {
            client: ClientAction::Close,
            backend: BackendAction::Close,
            reason: TeardownReason::Panic,
        },
    }
}

const TEARDOWN_IO_TIMEOUT: Duration = Duration::from_millis(250);

pub(crate) struct TeardownExecutor<'a> {
    pub(crate) frontend_write: &'a mut Box<dyn AsyncWrite + Send + Unpin>,
    pub(crate) backend_write: &'a mut Box<dyn AsyncWrite + Send + Unpin>,
}

impl TeardownExecutor<'_> {
    pub(crate) async fn execute(
        &mut self,
        trigger: TeardownTrigger,
    ) -> Result<TeardownDecision, RelayError> {
        let decision = decide_teardown(trigger);

        match decision.client {
            ClientAction::Fatal { code, message } => {
                let bytes = fatal_error_response(code, message);
                let _ = timeout(TEARDOWN_IO_TIMEOUT, self.frontend_write.write_all(&bytes)).await;
                let _ = timeout(TEARDOWN_IO_TIMEOUT, self.frontend_write.flush()).await;
            }
            ClientAction::NoticeThenFatal { code, message } => {
                let notice = error_response_bytes("NOTICE", "01000", "session idle timeout");
                let _ = timeout(TEARDOWN_IO_TIMEOUT, self.frontend_write.write_all(&notice)).await;
                let fatal = fatal_error_response(code, message);
                let _ = timeout(TEARDOWN_IO_TIMEOUT, self.frontend_write.write_all(&fatal)).await;
                let _ = timeout(TEARDOWN_IO_TIMEOUT, self.frontend_write.flush()).await;
            }
            ClientAction::OptionalFatal { code, message } => {
                let bytes = fatal_error_response(code, message);
                let _ = timeout(TEARDOWN_IO_TIMEOUT, self.frontend_write.write_all(&bytes)).await;
                let _ = timeout(TEARDOWN_IO_TIMEOUT, self.frontend_write.flush()).await;
            }
            ClientAction::HalfCloseThenClose => {
                let _ = timeout(TEARDOWN_IO_TIMEOUT, self.frontend_write.shutdown()).await;
            }
            ClientAction::Close => {}
        }

        match decision.backend {
            BackendAction::Close | BackendAction::ShutdownWrite => {
                let _ = timeout(TEARDOWN_IO_TIMEOUT, self.backend_write.shutdown()).await;
            }
            BackendAction::ForwardTerminateThenClose => {
                let terminate = [b'X', 0, 0, 0, 4];
                let _ = timeout(
                    TEARDOWN_IO_TIMEOUT,
                    self.backend_write.write_all(&terminate),
                )
                .await;
                let _ = timeout(TEARDOWN_IO_TIMEOUT, self.backend_write.flush()).await;
                let _ = timeout(TEARDOWN_IO_TIMEOUT, self.backend_write.shutdown()).await;
            }
            BackendAction::None => {}
        }

        Ok(decision)
    }
}

fn error_response_bytes(severity: &str, code: &str, message: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(b'S');
    body.extend_from_slice(severity.as_bytes());
    body.push(0);
    body.push(b'C');
    body.extend_from_slice(code.as_bytes());
    body.push(0);
    body.push(b'M');
    body.extend_from_slice(message.as_bytes());
    body.push(0);
    let mut out = Vec::with_capacity(1 + 4 + body.len());
    out.push(b'E');
    out.extend_from_slice(&((body.len() as u32).saturating_add(4)).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn teardown_decision_table() {
        let cases = [
            (
                TeardownTrigger::ClientTerminate,
                TeardownReason::ClientTerminate,
            ),
            (TeardownTrigger::ClientEof, TeardownReason::ClientEof),
            (TeardownTrigger::ClientReset, TeardownReason::ClientReset),
            (
                TeardownTrigger::BackendEof {
                    response_pending: true,
                },
                TeardownReason::BackendEofWhileWaiting,
            ),
            (
                TeardownTrigger::BackendEof {
                    response_pending: false,
                },
                TeardownReason::BackendEof,
            ),
            (
                TeardownTrigger::FramingViolation,
                TeardownReason::FramingViolation,
            ),
            (
                TeardownTrigger::ChaosTerminate {
                    send_error: false,
                    orderly: false,
                },
                TeardownReason::ChaosTerminate,
            ),
            (TeardownTrigger::AdminKill, TeardownReason::AdminKill),
            (TeardownTrigger::IdleTimeout, TeardownReason::IdleTimeout),
            (TeardownTrigger::Panic, TeardownReason::Panic),
        ];

        for (trigger, reason) in cases {
            assert_eq!(decide_teardown(trigger).reason, reason);
        }
    }

    #[test]
    fn backend_eof_with_and_without_pending_are_distinct() {
        let waiting = decide_teardown(TeardownTrigger::BackendEof {
            response_pending: true,
        });
        let idle = decide_teardown(TeardownTrigger::BackendEof {
            response_pending: false,
        });
        assert!(matches!(waiting.client, ClientAction::Fatal { .. }));
        assert_eq!(idle.client, ClientAction::Close);
    }

    #[test]
    fn chaos_terminate_actions_follow_flags() {
        let decision = decide_teardown(TeardownTrigger::ChaosTerminate {
            send_error: true,
            orderly: true,
        });
        assert!(matches!(
            decision.client,
            ClientAction::OptionalFatal { .. }
        ));
        assert_eq!(decision.backend, BackendAction::ForwardTerminateThenClose);
    }
}
