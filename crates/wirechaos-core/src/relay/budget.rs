use std::cell::Cell;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BudgetError {
    pub(crate) requested: usize,
    pub(crate) current: usize,
    pub(crate) max: usize,
}

impl Display for BudgetError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "in-flight budget exceed: requested {}, current {}, max {}",
            self.requested, self.current, self.max
        )
    }
}

impl std::error::Error for BudgetError {}

pub(crate) struct InFlightBudget {
    max: usize,
    used: Cell<usize>,
    high_water: Cell<usize>,
}

pub(crate) struct Reservation<'a> {
    used: &'a Cell<usize>,
    bytes: usize,
}

impl InFlightBudget {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            max,
            used: Cell::new(0),
            high_water: Cell::new(0),
        }
    }

    pub(crate) fn reserve(&self, bytes: usize) -> Result<Reservation<'_>, BudgetError> {
        let current = self.used.get();
        let next = current.saturating_add(bytes);

        if next > self.max {
            return Err(BudgetError {
                requested: bytes,
                current,
                max: self.max,
            });
        }

        self.used.set(next);

        if next > self.high_water.get() {
            self.high_water.set(next);
        }

        Ok(Reservation {
            used: &self.used,
            bytes,
        })
    }

    pub(crate) fn used(&self) -> usize {
        self.used.get()
    }

    pub(crate) fn high_water(&self) -> usize {
        self.high_water.get()
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.used.set(self.used.get().saturating_sub(self.bytes));
    }
}
