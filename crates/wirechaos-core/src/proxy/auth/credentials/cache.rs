use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::proxy::auth::verifier::Verifier;

/// The default cap on live cache entries.
pub const DEFAULT_MAX_ENTRIES: usize = 4096;

enum Entry {
    Positive(Arc<Verifier>, Instant),
    Negative(Instant),
}

pub struct LookupCache {
    positive_ttl: Duration,
    negative_ttl: Duration,
    max_entries: usize,
    entries: HashMap<String, Entry>,
}

impl LookupCache {
    pub fn new(positive_ttl: Duration, negative_ttl: Duration) -> Self {
        Self::with_capacity(positive_ttl, negative_ttl, DEFAULT_MAX_ENTRIES)
    }

    pub fn with_capacity(
        positive_ttl: Duration,
        negative_ttl: Duration,
        max_entries: usize,
    ) -> Self {
        Self {
            positive_ttl,
            negative_ttl,
            // A zero cap would make the cache pointless; keep at least one slot.
            max_entries: max_entries.max(1),
            entries: HashMap::new(),
        }
    }

    pub fn positive_ttl(&self) -> Duration {
        self.positive_ttl
    }

    pub fn negative_ttl(&self) -> Duration {
        self.negative_ttl
    }

    /// Resolve `username` from the cache.
    ///
    /// * `Some(Some(verifier))` — a live positive entry.
    /// * `Some(None)` — a live negative entry (user is known to be absent).
    /// * `None` — no live entry; the caller must consult the source.
    pub fn get(&mut self, username: &str, now: Instant) -> Option<Option<Arc<Verifier>>> {
        match self.entries.get(username) {
            Some(Entry::Positive(verifier, at))
                if now.saturating_duration_since(*at) <= self.positive_ttl =>
            {
                Some(Some(verifier.clone()))
            }
            Some(Entry::Negative(at))
                if now.saturating_duration_since(*at) <= self.negative_ttl =>
            {
                Some(None)
            }
            Some(_) => {
                self.entries.remove(username);
                None
            }
            None => None,
        }
    }

    /// Return the time a live negative entry was recorded, if any.
    pub fn get_negative(&mut self, username: &str, now: Instant) -> Option<Instant> {
        match self.get(username, now) {
            Some(None) => match self.entries.get(username) {
                Some(Entry::Negative(at)) => Some(*at),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn insert_positive(&mut self, username: &str, verifier: Arc<Verifier>, now: Instant) {
        self.evict_if_needed(now);
        self.entries
            .insert(username.to_owned(), Entry::Positive(verifier, now));
    }

    pub fn insert_negative(&mut self, username: &str, now: Instant) {
        self.evict_if_needed(now);
        self.entries
            .insert(username.to_owned(), Entry::Negative(now));
    }

    /// Drop a single entry, used by the control-plane's "forget user" call.
    pub fn forget(&mut self, username: &str) {
        self.entries.remove(username);
    }

    fn evict_if_needed(&mut self, now: Instant) {
        if self.entries.len() < self.max_entries {
            return;
        }

        self.entries.retain(|_, entry| match entry {
            Entry::Positive(_, at) => now.saturating_duration_since(*at) < self.positive_ttl,
            Entry::Negative(at) => now.saturating_duration_since(*at) < self.negative_ttl,
        });

        if self.entries.len() >= self.max_entries {
            // Everything is still live; shed the whole map rather than let it
            // grow without bound. The next lookup repopulates it.
            self.entries.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_results_are_cached_briefly_and_never_forever() {
        let mut cache = LookupCache::new(Duration::from_secs(60), Duration::from_secs(5));
        cache.insert_negative("ghost", Instant::now());

        assert!(cache.get_negative("ghost", Instant::now()).is_some());
        assert!(
            cache
                .get_negative("ghost", Instant::now() + Duration::from_secs(6))
                .is_none(),
            "a provisioned user must become visible again within seconds"
        );
    }
}
