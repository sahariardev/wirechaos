use crate::relay::classification::{MessageInfo, MessageKind};

pub(crate) struct CapturedQuery {
    pub(crate) text: String,
    pub(crate) truncated: bool,
}

pub(crate) struct QueryCapture {
    last: Option<CapturedQuery>,
    enabled: bool,
    max_query_size_in_bytes: usize,
}

impl QueryCapture {
    pub(crate) fn new(enabled: bool, max_query_size_in_bytes: usize) -> Self {
        Self {
            enabled,
            max_query_size_in_bytes,
            last: None,
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn enable(&mut self) {
        self.enabled = true;
    }

    pub(crate) fn disable(&mut self) {
        self.enabled = false;
    }

    pub(crate) fn last(&self) -> Option<&CapturedQuery> {
        self.last.as_ref()
    }

    pub(crate) fn capture(&mut self, info: &MessageInfo, body: &[u8]) {
        match &info.kind {
            MessageKind::Query | MessageKind::Parse => {
                let mut truncated = false;
                if body.len() > self.max_query_size_in_bytes {
                    truncated = true
                }

                let mut query = String::with_capacity(self.max_query_size_in_bytes);

                if truncated {
                    query = String::from_utf8_lossy(&body[..self.max_query_size_in_bytes])
                        .parse()
                        .unwrap();
                } else {
                    query = String::from_utf8_lossy(body).parse().unwrap();
                }

                self.last = Some(CapturedQuery {
                    truncated,
                    text: query,
                })
            }
            _ => {}
        }
    }
}
