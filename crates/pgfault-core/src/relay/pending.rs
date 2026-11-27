use crate::relay::classification::MessageKind;

#[derive(Debug)]
pub(crate) struct PendingQueries {
    count: u32,
}

impl PendingQueries {
    pub(crate) fn new() -> Self {
        Self { count: 0 }
    }

    pub(crate) fn observe_frontend(&mut self, kind: MessageKind) {
        use MessageKind::*;
        match kind {
            Query | Parse | Bind | Describe | Execute | Close | Sync | FunctionCall => {
                self.count = self.count.saturating_add(1);
            }
            _ => {}
        }
    }

    pub(crate) fn observe_backend(&mut self, kind: MessageKind) {
        if kind == MessageKind::ReadyForQuery {
            self.reset_on_ready();
        }
    }

    #[allow(dead_code, reason = "consumed by suppression windows in 6.22")]
    pub(crate) fn pending(&self) -> u32 {
        self.count
    }

    #[allow(dead_code, reason = "consumed by suppression windows in 6.22")]
    pub(crate) fn has_pending(&self) -> bool {
        self.count > 0
    }

    pub(crate) fn reset_on_ready(&mut self) {
        self.count = 0;
    }
}

impl Default for PendingQueries {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::classification::classify;
    use crate::relay::classification::Direction::{BackendToFrontend, FrontendToBackend};

    fn frontend(kind_byte: u8) -> MessageKind {
        classify(FrontendToBackend, kind_byte).kind
    }

    fn backend(kind_byte: u8) -> MessageKind {
        classify(BackendToFrontend, kind_byte).kind
    }

    #[test]
    fn pending_query_counting_pairs_queries_with_ready_for_query() {
        let mut p = PendingQueries::new();
        p.observe_frontend(frontend(b'Q'));
        assert_eq!(p.pending(), 1);
        assert!(p.has_pending());

        p.observe_backend(backend(b'Z'));
        assert_eq!(p.pending(), 0);
        assert!(!p.has_pending());
    }

    #[test]
    fn pipelined_extended_work_increments_per_message() {
        let mut p = PendingQueries::new();
        for kind_byte in [b'P', b'B', b'D', b'E', b'S'] {
            p.observe_frontend(frontend(kind_byte));
        }
        assert_eq!(p.pending(), 5);

        p.observe_backend(backend(b'Z'));
        assert_eq!(p.pending(), 0);
    }

    #[test]
    fn flush_does_not_increment_pending() {
        let mut p = PendingQueries::new();
        p.observe_frontend(frontend(b'Q'));
        p.observe_frontend(frontend(b'H'));
        assert_eq!(p.pending(), 1);
    }

    #[test]
    fn multiple_ready_for_query_never_underflows() {
        let mut p = PendingQueries::new();
        for _ in 0..5 {
            p.observe_backend(backend(b'Z'));
        }
        assert_eq!(p.pending(), 0);
    }

    #[test]
    fn pending_counter_saturates_without_allocating() {
        let mut p = PendingQueries::new();
        p.count = u32::MAX - 1;
        p.observe_frontend(frontend(b'Q'));
        p.observe_frontend(frontend(b'Q'));
        assert_eq!(p.pending(), u32::MAX);
    }
}
