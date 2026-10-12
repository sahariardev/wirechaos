//! Logging must be initialised exactly once per process.
//!
//! This is deliberately its own integration-test binary: the tracing subscriber
//! is process-global, so any other test installing one first would make the
//! assertions meaningless.

#[test]
fn logging_initialises_exactly_once() {
    assert!(
        wirechaos_core::init_logging().is_ok(),
        "the first call installs the subscriber"
    );
    assert!(
        wirechaos_core::init_logging().is_err(),
        "a second call must report the conflict, not panic and not leak a second subscriber"
    );
}
