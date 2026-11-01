use crate::proxy::config::Config;
use std::time::Duration;

pub struct RelayConfig {
    max_message_size: usize,

    idle_timeout: Option<Duration>,

    pool_max_bucket: usize,

    max_inflight_bytes: usize,

    capture_query_text: bool,

    max_captured_query_bytes: usize,
}

impl RelayConfig {
    pub fn new(config: &Config) -> Self {
        //todo:: validation error

        let idle_timeout = None;

        Self {
            max_message_size: config.limits.max_message_size,
            idle_timeout,
            pool_max_bucket: config.limits.pool_max_bucket,
            max_inflight_bytes: config.limits.max_inflight_bytes,
            capture_query_text: config.limits.capture_query_text,
            max_captured_query_bytes: config.limits.max_inflight_bytes,
        }
    }
}
