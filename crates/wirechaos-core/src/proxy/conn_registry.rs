use std::sync::{Arc, PoisonError, RwLock};

/// Default connection cap, matching PostgreSQL's `max_connections` default.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 100;

pub struct ConnRegistry {
    inner: Arc<RwLock<Inner>>,
}

impl Clone for ConnRegistry {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

struct Inner {
    live: u32,
    max: u32,
}

impl ConnRegistry {
    pub fn new(max: u32) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner { live: 0, max })),
        }
    }

    pub fn try_acquire(&self) -> Option<ConnPermit> {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);

        if inner.live >= inner.max {
            return None;
        }

        inner.live += 1;
        Some(ConnPermit {
            registry: self.clone(),
        })
    }

    pub fn live(&self) -> u32 {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .live
    }
}

pub struct ConnPermit {
    registry: ConnRegistry,
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        let mut inner = self
            .registry
            .inner
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        inner.live = inner.live.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permit_is_release_on_drop() {
        let registry = ConnRegistry::new(2);
        let a = registry.try_acquire().expect("first slot");
        let _b = registry.try_acquire().expect("second slot");

        assert!(registry.try_acquire().is_none(), "third must be refused");
        drop(a);
        assert!(registry.try_acquire().is_some(), "free slot is reusable");
    }

    #[test]
    fn clone_share_the_counter() {
        let registry = ConnRegistry::new(1);
        let clone = registry.clone();

        let _permit = registry.try_acquire().expect("first slot");
        assert!(
            clone.try_acquire().is_none(),
            "clones must share the same count"
        );
    }

    #[test]
    fn a_slot_is_released_even_if_the_holder_panics() {
        let registry = ConnRegistry::new(1);

        let result = std::panic::catch_unwind({
            let registry = registry.clone();
            move || {
                let _permit = registry.try_acquire().expect("slot");
                panic!("session task panics while holding the permit");
            }
        });

        assert!(result.is_err(), "the panicking closure must unwind");
        assert_eq!(registry.live(), 0, "an abrupt exit must not leak a slot");
    }
}
