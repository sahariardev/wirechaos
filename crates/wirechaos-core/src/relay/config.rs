use crate::proxy::config::Config;
use std::fmt;
use std::time::Duration;

#[derive(Debug, Clone)]
pub(crate) struct RelayConfig {
    pub(crate) max_message_size: usize,
    pub(crate) idle_timeout: Option<Duration>,
    pub(crate) pool_max_bucket: usize,
    pub(crate) max_inflight_bytes: usize,
    pub(crate) capture_query_text: bool,
    pub(crate) max_captured_query_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayConfigError {
    pub(crate) field: &'static str,
    pub(crate) value: String,
    pub(crate) expected: String,
}

impl fmt::Display for RelayConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {}: {}", self.field, self.value, self.expected)
    }
}

impl std::error::Error for RelayConfigError {}

fn invalid(field: &'static str, value: usize, expected: String) -> RelayConfigError {
    RelayConfigError {
        field,
        value: value.to_string(),
        expected,
    }
}

impl RelayConfig {
    pub(crate) fn from_config(config: &Config) -> Result<RelayConfig, RelayConfigError> {
        let limits = &config.limits;

        if limits.max_message_size < 5 {
            return Err(invalid(
                "limits.max_message_size",
                limits.max_message_size,
                "must be at least 5 (the smallest regular frame is 5 bytes)".to_owned(),
            ));
        }

        if limits.pool_max_bucket == 0 {
            return Err(invalid(
                "limits.pool_max_bucket",
                limits.pool_max_bucket,
                "must be greater than 0".to_owned(),
            ));
        }

        if limits.pool_max_bucket > limits.max_message_size {
            return Err(invalid(
                "limits.pool_max_bucket",
                limits.pool_max_bucket,
                format!(
                    "must be <= limits.max_message_size ({})",
                    limits.max_message_size
                ),
            ));
        }

        if limits.max_inflight_bytes == 0 {
            return Err(invalid(
                "limits.max_inflight_bytes",
                limits.max_inflight_bytes,
                "must be greater than 0".to_owned(),
            ));
        }

        if limits.capture_query_text && limits.max_captured_query_bytes == 0 {
            return Err(invalid(
                "limits.max_captured_query_bytes",
                limits.max_captured_query_bytes,
                "must be greater than 0".to_owned(),
            ));
        }

        if limits.max_captured_query_bytes > limits.max_message_size {
            return Err(invalid(
                "limits.max_captured_query_bytes",
                limits.max_captured_query_bytes,
                format!(
                    "must be <= limits.max_message_size ({})",
                    limits.max_message_size
                ),
            ));
        }

        let idle_timeout = match limits.idle_timeout_ms {
            0 => None,
            ms => Some(Duration::from_millis(ms)),
        };

        Ok(Self {
            max_message_size: limits.max_message_size,
            idle_timeout,
            pool_max_bucket: limits.pool_max_bucket,
            max_inflight_bytes: limits.max_inflight_bytes,
            capture_query_text: limits.capture_query_text,
            max_captured_query_bytes: limits.max_captured_query_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_yaml(text: &str) -> Result<RelayConfig, RelayConfigError> {
        let config = Config::from_yaml(text).expect("valid YAML");
        RelayConfig::from_config(&config)
    }

    #[test]
    fn relay_defaults_match_design_limits() {
        let relay = from_yaml("{}").expect("defaults are valid");

        assert_eq!(relay.max_message_size, 1 << 30);
        assert_eq!(relay.pool_max_bucket, 64 * 1024);
        assert_eq!(relay.max_inflight_bytes, 1 * 1024 * 1024);
        assert!(relay.capture_query_text);
        assert_eq!(relay.max_captured_query_bytes, 8 * 1024);
        assert_eq!(relay.idle_timeout, None);
    }

    #[test]
    fn relay_limits_override_from_yaml() {
        let relay = from_yaml(
            "limits:\n  max_message_size: 65536\n  pool_max_bucket: 1024\n  max_inflight_bytes: 2048\n  capture_query_text: false\n  max_captured_query_bytes: 512\n  idle_timeout_ms: 250\n",
        )
        .expect("valid overrides");

        assert_eq!(relay.max_message_size, 65_536);
        assert_eq!(relay.pool_max_bucket, 1_024);
        assert_eq!(relay.max_inflight_bytes, 2_048);
        assert!(!relay.capture_query_text);
        assert_eq!(relay.max_captured_query_bytes, 512);
        assert_eq!(relay.idle_timeout, Some(Duration::from_millis(250)));
    }

    #[test]
    fn zero_pool_bucket_is_rejected() {
        let err = from_yaml("limits:\n  pool_max_bucket: 0\n").expect_err("0 bucket");

        assert_eq!(err.field, "limits.pool_max_bucket");
        assert_eq!(err.value, "0");
        assert_eq!(err.expected, "must be greater than 0");
    }

    #[test]
    fn zero_inflight_budget_is_rejected() {
        let err = from_yaml("limits:\n  max_inflight_bytes: 0\n").expect_err("0 inflight");

        assert_eq!(err.field, "limits.max_inflight_bytes");
        assert_eq!(err.value, "0");
    }

    #[test]
    fn capture_cap_above_message_cap_is_rejected() {
        let err =
            from_yaml("limits:\n  max_message_size: 65536\n  max_captured_query_bytes: 1048576\n")
                .expect_err("capture cap > message cap");

        assert_eq!(err.field, "limits.max_captured_query_bytes");
        assert_eq!(err.value, "1048576");
        assert_eq!(err.expected, "must be <= limits.max_message_size (65536)");
    }

    #[test]
    fn capture_can_be_disabled() {
        // Disabled + cap 0 is explicitly allowed (spec §8 table).
        let relay =
            from_yaml("limits:\n  capture_query_text: false\n  max_captured_query_bytes: 0\n")
                .expect("disabled capture with 0 cap is allowed");

        assert!(!relay.capture_query_text);
        assert_eq!(relay.max_captured_query_bytes, 0);
    }

    #[test]
    fn idle_timeout_zero_means_disabled() {
        let relay = from_yaml("limits:\n  idle_timeout_ms: 0\n").expect("valid");

        assert_eq!(relay.idle_timeout, None);
    }

    #[test]
    fn idle_timeout_milliseconds_are_converted() {
        let relay = from_yaml("limits:\n  idle_timeout_ms: 1500\n").expect("valid");

        assert_eq!(relay.idle_timeout, Some(Duration::from_millis(1_500)));
    }

    #[test]
    fn invalid_limit_error_names_the_field_value_and_range() {
        let err = from_yaml("limits:\n  pool_max_bucket: 0\n").expect_err("invalid");

        assert!(err.field.starts_with("limits."));
        assert!(!err.value.is_empty());
        assert!(!err.expected.is_empty());
        assert!(err.to_string().contains(err.field));
        assert!(err.to_string().contains(&err.value));
    }

    #[test]
    fn message_size_below_smallest_frame_is_rejected() {
        let err = from_yaml("limits:\n  max_message_size: 4\n").expect_err("< 5");

        assert_eq!(err.field, "limits.max_message_size");
        assert_eq!(err.value, "4");
    }
}
