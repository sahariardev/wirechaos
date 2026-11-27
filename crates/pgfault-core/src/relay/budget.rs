#![allow(dead_code)]
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

#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_release_is_symmetric() {
        let budget = InFlightBudget::new(1024 * 1024);
        let first = budget.reserve(512 * 1024).expect("first");
        let second = budget.reserve(512 * 1024).expect("second");
        assert_eq!(budget.used(), 1024 * 1024);
        assert!(budget.reserve(1).is_err());
        drop(first);
        assert_eq!(budget.used(), 512 * 1024);
        drop(second);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn exhaustion_reports_requested_current_and_max() {
        let budget = InFlightBudget::new(10);
        let _reservation = budget.reserve(8).expect("8");
        let error = budget.reserve(5).expect_err("budget exceeded");
        assert_eq!(error.requested, 5);
        assert_eq!(error.current, 8);
        assert_eq!(error.max, 10);
    }

    #[test]
    fn high_water_tracks_the_peak_not_the_current_value() {
        let budget = InFlightBudget::new(100);
        let a = budget.reserve(40).expect("a");
        let b = budget.reserve(40).expect("b");
        assert_eq!(budget.high_water(), 80);
        drop(a);
        drop(b);
        assert_eq!(budget.used(), 0);
        assert_eq!(budget.high_water(), 80);
    }

    #[test]
    fn zero_byte_reservation_is_a_no_op() {
        let budget = InFlightBudget::new(10);
        let reservation = budget.reserve(0).expect("zero");
        assert_eq!(budget.used(), 0);
        drop(reservation);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn budgets_are_independent() {
        let frontend = InFlightBudget::new(10);
        let backend = InFlightBudget::new(10);
        let _front = frontend.reserve(10).expect("front");
        assert!(frontend.reserve(1).is_err());
        assert!(backend.reserve(10).is_ok());
    }
}
