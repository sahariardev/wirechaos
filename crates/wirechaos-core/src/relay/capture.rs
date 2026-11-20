use crate::relay::classification::{Direction, MessageInfo, MessageKind};

#[derive(Debug)]
#[allow(dead_code, reason = "read by the hook context added in 6.20")]
pub(crate) struct CapturedQuery {
    pub(crate) text: String,
    pub(crate) truncated: bool,
}

#[derive(Debug)]
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

    #[allow(dead_code, reason = "consumed by the hook context added in 6.20")]
    pub(crate) fn last(&self) -> Option<&CapturedQuery> {
        self.last.as_ref()
    }

    pub(crate) fn capture(&mut self, info: &MessageInfo, body: &[u8]) {
        if !self.enabled {
            self.last = None;
            return;
        }
        
        if info.direction != Direction::FrontendToBackend {
            return;
        }

        let sql = match info.kind {
            MessageKind::Query => query_sql(body),
            MessageKind::Parse => parse_sql(body),
            _ => return,
        };

        let cap = self.max_query_size_in_bytes;
        let truncated = sql.len() > cap;
        let take = sql.len().min(cap);
        let mut text = String::from_utf8_lossy(&sql[..take]).into_owned();
        
        if text.len() > cap {
            let mut end = cap;
            while end > 0 && !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }

        self.last = Some(CapturedQuery { text, truncated });
    }
}

fn query_sql(body: &[u8]) -> &[u8] {
    let mut parts = body.splitn(2, |byte| *byte == 0);
    parts.next().unwrap_or(body)
}

fn parse_sql(body: &[u8]) -> &[u8] {
    let mut parts = body.splitn(3, |byte| *byte == 0);
    let _statement_name = parts.next();
    parts.next().unwrap_or(&[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::classification::classify;

    fn frontend(kind_byte: u8) -> MessageInfo {
        classify(Direction::FrontendToBackend, kind_byte)
    }

    fn backend(kind_byte: u8) -> MessageInfo {
        classify(Direction::BackendToFrontend, kind_byte)
    }

    #[test]
    fn query_capture_is_capped_and_flagged() {
        let mut capture = QueryCapture::new(true, 8);
        capture.capture(&frontend(b'Q'), b"SELECT something\0");

        let last = capture.last().expect("captured");
        assert_eq!(last.text, "SELECT s");
        assert_eq!(last.text.len(), 8);
        assert!(last.truncated);
    }

    #[test]
    fn parse_message_captures_only_the_sql() {
        let mut capture = QueryCapture::new(true, 64);
        // name\0 SQL \0 parameter type data
        capture.capture(&frontend(b'P'), b"stmt\0SELECT 1\0\0\0");

        let last = capture.last().expect("captured");
        assert_eq!(last.text, "SELECT 1");
        assert!(!last.truncated);
    }

    #[test]
    fn capture_can_be_disabled() {
        let mut capture = QueryCapture::new(false, 64);
        capture.capture(&frontend(b'Q'), b"SELECT 1\0");

        assert!(capture.last().is_none());
    }

    #[test]
    fn backend_messages_do_not_change_capture() {
        let mut capture = QueryCapture::new(true, 64);
        capture.capture(&frontend(b'Q'), b"SELECT 1\0");

        capture.capture(&backend(b'Q'), b"NOT SQL\0");
        capture.capture(&backend(b'Z'), b"I");

        let last = capture.last().expect("unchanged");
        assert_eq!(last.text, "SELECT 1");
    }

    #[test]
    fn invalid_utf8_is_lossy_not_fatal() {
        let mut capture = QueryCapture::new(true, 64);
        capture.capture(&frontend(b'Q'), &[0xFF, 0xFE, 0]);

        let last = capture.last().expect("captured");
        assert!(last.text.contains('\u{FFFD}'));
        assert!(!last.truncated);
    }

    #[test]
    fn empty_sql_is_stored_empty_not_truncated() {
        let mut capture = QueryCapture::new(true, 8);
        capture.capture(&frontend(b'Q'), b"\0");

        let last = capture.last().expect("captured");
        assert_eq!(last.text, "");
        assert!(!last.truncated);
    }

    #[test]
    fn retained_text_never_exceeds_the_byte_cap_after_lossy_decoding() {
        let mut capture = QueryCapture::new(true, 1);
        capture.capture(&frontend(b'Q'), &[0xFF, 0xFE, 0]);

        let last = capture.last().expect("captured");
        assert!(last.text.len() <= 1);
        assert!(last.truncated);
    }
}
