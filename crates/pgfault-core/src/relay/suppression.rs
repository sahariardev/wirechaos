use crate::relay::classification::{MessageInfo, MessageKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SuppressionAction {
    Forward,
    Drop,
}

#[derive(Debug, Default)]
pub(crate) struct SuppressionWindow {
    armed: u32,
}

impl SuppressionWindow {
    pub(crate) fn new() -> Self {
        Self { armed: 0 }
    }

    pub(crate) fn arm(&mut self) {
        self.armed = self.armed.saturating_add(1);
    }

    #[allow(dead_code)]
    pub(crate) fn is_armed(&self) -> bool {
        self.armed > 0
    }

    pub(crate) fn observe_backend(&mut self, info: &MessageInfo) -> SuppressionAction {
        if self.armed == 0 {
            return SuppressionAction::Forward;
        }

        // The ReadyForQuery that ends the hidden round belongs to the window.
        if info.kind == MessageKind::ReadyForQuery {
            self.take_ready();
        }

        SuppressionAction::Drop
    }

    pub(crate) fn take_ready(&mut self) {
        self.armed = self.armed.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::classification::classify;
    use crate::relay::classification::Direction::{BackendToFrontend, FrontendToBackend};

    fn backend(kind: u8) -> MessageInfo {
        classify(BackendToFrontend, kind)
    }

    #[test]
    fn suppression_hides_one_query_response() {
        let mut window = SuppressionWindow::new();
        window.arm();

        for kind in [b'T', b'D', b'N', b'C', b'Z'] {
            assert_eq!(
                window.observe_backend(&backend(kind)),
                SuppressionAction::Drop
            );
        }
        assert!(!window.is_armed());
    }

    #[test]
    fn next_query_response_is_forwarded() {
        let mut window = SuppressionWindow::new();
        window.arm();
        let _ = window.observe_backend(&backend(b'Z'));
        assert_eq!(
            window.observe_backend(&backend(b'T')),
            SuppressionAction::Forward
        );
    }

    #[test]
    fn ready_closes_exactly_one_window() {
        let mut window = SuppressionWindow::new();
        window.arm();
        window.arm();
        let _ = window.observe_backend(&backend(b'Z'));
        assert!(window.is_armed());
        let _ = window.observe_backend(&backend(b'Z'));
        assert!(!window.is_armed());
    }

    #[test]
    fn notice_inside_window_is_suppressed() {
        let mut window = SuppressionWindow::new();
        window.arm();
        assert_eq!(
            window.observe_backend(&backend(b'N')),
            SuppressionAction::Drop
        );
    }

    #[test]
    fn frontend_messages_are_not_suppression_input() {
        let mut window = SuppressionWindow::new();
        window.arm();
        // The API is backend-only; this test documents the boundary.
        let info = classify(FrontendToBackend, b'Q');
        assert_eq!(window.observe_backend(&info), SuppressionAction::Drop);
        assert!(window.is_armed());
    }
}
