#![allow(dead_code)]

mod budget;
mod buffer;
mod capture;
mod classification;
mod config;
mod counters;
mod degrade;
mod digest;
mod engine;
mod error;
mod framed_pump;
mod header;
mod hook;
mod observe;
mod pending;
mod raw_pump;
mod reader;
mod sessions;
mod state;
mod suppression;
mod teardown;
mod writer;

#[allow(unused_imports)]
pub(crate) use config::{RelayConfig, RelayConfigError};
#[allow(unused_imports)]
pub(crate) use error::{RelayError, TeardownReason};
#[allow(unused_imports)]
pub(crate) use framed_pump::PumpOutcome;
#[allow(unused_imports)]
pub(crate) use sessions::{run, run_framed, run_raw, Mode, RelayOutcome, RelaySession, RunOutcome};
use tokio::sync::watch;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionFilters {
    pub(crate) user: Option<String>,
    pub(crate) database: Option<String>,
    pub(crate) application_name: Option<String>,
}

pub(crate) trait ModePlan: Send + Sync {
    fn epoch(&self) -> u64;
    fn could_match(&self, filters: &SessionFilters) -> bool;
}

/// Default plan used until the rule engine is wired in.
pub(crate) struct NoChaosPlan;

impl ModePlan for NoChaosPlan {
    fn epoch(&self) -> u64 {
        0
    }

    fn could_match(&self, _filters: &SessionFilters) -> bool {
        false
    }
}

pub(crate) fn decide_mode(
    plan: &dyn ModePlan,
    filters: &SessionFilters,
    chaos_enabled: bool,
) -> Mode {
    if !chaos_enabled || !plan.could_match(filters) {
        Mode::Raw
    } else {
        Mode::Framed
    }
}

#[derive(Debug, Clone)]
pub(crate) struct EpochWatcher {
    rx: watch::Receiver<u64>,
    last: u64,
}

impl EpochWatcher {
    pub(crate) fn new(rx: watch::Receiver<u64>) -> Self {
        let last = *rx.borrow();
        Self { rx, last }
    }

    pub(crate) fn current(&self) -> u64 {
        *self.rx.borrow()
    }

    //non-blocking
    pub(crate) fn changed(&mut self) -> bool {
        if self.rx.has_changed().unwrap_or(false) {
            self.last = *self.rx.borrow_and_update();
            true
        } else {
            false
        }
    }

    //blocking
    pub(crate) async fn wait(&mut self) -> u64 {
        let _ = self.rx.changed().await;
        self.last = *self.rx.borrow_and_update();
        self.last
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Plan {
        matches: bool,
        epoch: u64,
    }

    impl ModePlan for Plan {
        fn epoch(&self) -> u64 {
            self.epoch
        }

        fn could_match(&self, _filters: &SessionFilters) -> bool {
            self.matches
        }
    }

    #[test]
    fn mode_decision_table() {
        let filters = SessionFilters::default();
        let matching = Plan {
            matches: true,
            epoch: 1,
        };
        let non_matching = Plan {
            matches: false,
            epoch: 1,
        };

        assert_eq!(decide_mode(&matching, &filters, false), Mode::Raw);
        assert_eq!(decide_mode(&non_matching, &filters, true), Mode::Raw);
        assert_eq!(decide_mode(&matching, &filters, true), Mode::Framed);
    }

    #[test]
    fn default_plan_is_raw() {
        let filters = SessionFilters::default();
        assert_eq!(decide_mode(&NoChaosPlan, &filters, true), Mode::Raw);
    }

    #[tokio::test]
    async fn epoch_watch_observes_a_bump() {
        let (tx, rx) = tokio::sync::watch::channel(0);
        let mut watcher = EpochWatcher::new(rx);
        tx.send(1).expect("bump");
        assert!(watcher.changed());
        assert_eq!(watcher.current(), 1);
    }
}
