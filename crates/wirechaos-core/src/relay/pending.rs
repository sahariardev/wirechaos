use crate::relay::classification::{MessageInfo, MessageKind};

pub(crate) struct PendingQueries {
    count: u32,
}

impl PendingQueries {
    pub(crate) fn new() -> Self {
        Self { count: 0 }
    }

    pub(crate) fn observe_frontend(&mut self, info: &MessageInfo) {
        use MessageKind::*;
        match info.kind {
            Query | Parse | Bind | Describe | Execute | Close | Sync | FunctionCall => {
                self.count += 1
            }
            _ => {}
        }
    }

    pub(crate) fn observe_backend(&mut self, info: &MessageInfo) {
        if info.kind == MessageKind::ReadyForQuery {
            self.count = 0;
        }
    }

    pub(crate) fn pending(&self) -> u32 {
        self.count
    }

    pub(crate) fn has_pending(&self) -> bool {
        self.count > 0
    }

    pub(crate) fn reset_on_ready(&mut self) {
        self.count = 0;
    }
}
