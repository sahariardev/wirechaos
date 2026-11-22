mod buffer;
mod capture;
mod classification;
mod config;
mod error;
mod framed_pump;
mod header;
mod pending;
mod raw_pump;
mod reader;
mod sessions;
mod state;
mod writer;
mod degrade;

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
