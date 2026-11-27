#![allow(dead_code)]
use crate::relay::classification::Direction;
use crate::relay::error::TeardownReason;
use crate::relay::header::ReadPath;
use crate::relay::sessions::Mode;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DirectionCounters {
    pub(crate) messages: u64,
    pub(crate) bytes: u64,
    pub(crate) pooled_frames: u64,
    pub(crate) streamed_frames: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CounterSnapshot {
    pub(crate) frontend: DirectionCounters,
    pub(crate) backend: DirectionCounters,
    pub(crate) mode: Mode,
    pub(crate) in_flight_high_water: usize,
    pub(crate) teardown_reason: Option<TeardownReason>,
}

#[derive(Debug, Clone)]
pub(crate) struct RelayCounters {
    frontend: DirectionCounters,
    backend: DirectionCounters,
    mode: Mode,
    in_flight_high_water: usize,
    teardown_reason: Option<TeardownReason>,
}

impl RelayCounters {
    pub(crate) fn new(mode: Mode) -> Self {
        Self {
            frontend: DirectionCounters::default(),
            backend: DirectionCounters::default(),
            mode,
            in_flight_high_water: 0,
            teardown_reason: None,
        }
    }

    pub(crate) fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    pub(crate) fn mode(&self) -> Mode {
        self.mode
    }

    pub(crate) fn observe_written(&mut self, direction: Direction, bytes: usize) {
        let target = match direction {
            Direction::FrontendToBackend => &mut self.frontend,
            Direction::BackendToFrontend => &mut self.backend,
        };
        target.messages = target.messages.saturating_add(1);
        target.bytes = target.bytes.saturating_add(bytes as u64);
    }

    pub(crate) fn observe_read_path(&mut self, direction: Direction, path: ReadPath) {
        let target = match direction {
            Direction::FrontendToBackend => &mut self.frontend,
            Direction::BackendToFrontend => &mut self.backend,
        };
        match path {
            ReadPath::HeaderOnly => {}
            ReadPath::Pooled => target.pooled_frames = target.pooled_frames.saturating_add(1),
            ReadPath::Streamed => target.streamed_frames = target.streamed_frames.saturating_add(1),
        }
    }

    pub(crate) fn observe_high_water(&mut self, bytes: usize) {
        if bytes > self.in_flight_high_water {
            self.in_flight_high_water = bytes;
        }
    }

    pub(crate) fn set_teardown_reason(&mut self, reason: TeardownReason) {
        self.teardown_reason = Some(reason);
    }

    pub(crate) fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            frontend: self.frontend,
            backend: self.backend,
            mode: self.mode,
            in_flight_high_water: self.in_flight_high_water,
            teardown_reason: self.teardown_reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_match_a_scripted_workload() {
        let mut counters = RelayCounters::new(Mode::Framed);
        counters.observe_written(Direction::FrontendToBackend, 5);
        counters.observe_written(Direction::FrontendToBackend, 13);
        counters.observe_written(Direction::BackendToFrontend, 9);
        counters.observe_read_path(Direction::FrontendToBackend, ReadPath::HeaderOnly);
        counters.observe_read_path(Direction::BackendToFrontend, ReadPath::Pooled);

        let snapshot = counters.snapshot();
        assert_eq!(snapshot.frontend.messages, 2);
        assert_eq!(snapshot.frontend.bytes, 18);
        assert_eq!(snapshot.frontend.pooled_frames, 0);
        assert_eq!(snapshot.backend.messages, 1);
        assert_eq!(snapshot.backend.bytes, 9);
        assert_eq!(snapshot.backend.pooled_frames, 1);
    }

    #[test]
    fn counters_are_independent_per_direction() {
        let mut counters = RelayCounters::new(Mode::Raw);
        counters.observe_written(Direction::FrontendToBackend, 100);
        counters.observe_written(Direction::BackendToFrontend, 7);
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.frontend.bytes, 100);
        assert_eq!(snapshot.backend.bytes, 7);
    }

    #[test]
    fn streamed_and_pooled_frames_are_counted_once() {
        let mut counters = RelayCounters::new(Mode::Framed);
        counters.observe_read_path(Direction::FrontendToBackend, ReadPath::Pooled);
        counters.observe_read_path(Direction::FrontendToBackend, ReadPath::Streamed);
        counters.observe_written(Direction::FrontendToBackend, 300 * 1024 * 1024 + 5);

        let snapshot = counters.snapshot();
        assert_eq!(snapshot.frontend.pooled_frames, 1);
        assert_eq!(snapshot.frontend.streamed_frames, 1);
        assert_eq!(snapshot.frontend.messages, 1);
        assert_eq!(snapshot.frontend.bytes, (300 * 1024 * 1024 + 5) as u64);
    }

    #[test]
    fn mode_and_teardown_reason_survive_snapshot() {
        let mut counters = RelayCounters::new(Mode::Raw);
        counters.set_mode(Mode::Framed);
        counters.set_teardown_reason(TeardownReason::ClientEof);
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.mode, Mode::Framed);
        assert_eq!(snapshot.teardown_reason, Some(TeardownReason::ClientEof));
    }

    #[test]
    fn high_water_is_the_maximum() {
        let mut counters = RelayCounters::new(Mode::Framed);
        counters.observe_high_water(10);
        counters.observe_high_water(5);
        counters.observe_high_water(20);
        assert_eq!(counters.snapshot().in_flight_high_water, 20);
    }
}
