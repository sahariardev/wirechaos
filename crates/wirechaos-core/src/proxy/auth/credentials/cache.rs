use crate::proxy::auth::verifier::Verifier;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub enum Entry {
    POSITIVE(Arc<Verifier>, Instant),
    NEGATIVE(Instant),
}

pub struct TtlCache {
    positive_ttl: Duration,
    negative_ttl: Duration,
    entries: HashMap<String, Entry>,
    max_entries: usize,
}

impl TtlCache {
    pub fn new(positive_ttl: Duration, negative_ttl: Duration, max_entries: usize) -> Self {
        Self {
            positive_ttl,
            negative_ttl,
            entries: HashMap::new(),
            max_entries,
        }
    }

    pub fn get(&mut self, username: &str, now: Instant) -> Option<Option<Arc<Verifier>>> {
        match self.entries.get(username) {
            Some(Entry::POSITIVE(val, at)) if now.duration_since(*at) <= self.positive_ttl => {
                Some(Some(val.clone()))
            }

            Some(Entry::NEGATIVE(at)) if now.duration_since(*at) <= self.negative_ttl => Some(None),
            Some(_) => {
                self.entries.remove(username);
                None
            }

            None => None,
        }
    }

    pub fn add_positive_entry(&mut self, username: &str, verifier: Arc<Verifier>, now: Instant) {
        self.evict_if_needed();
        self.entries
            .insert(username.to_owned(), Entry::POSITIVE(verifier, now));
    }

    pub fn add_negative_entry(&mut self, username: &str, now: Instant) {
        self.evict_if_needed();
        self.entries
            .insert(username.to_owned(), Entry::NEGATIVE(now));
    }

    fn evict_if_needed(&mut self) {
        if self.entries.len() >= self.max_entries {
            self.entries.retain(|_, entry| match entry {
                Entry::POSITIVE(_, at) => at.elapsed() < self.positive_ttl,
                Entry::NEGATIVE(at) => at.elapsed() < self.negative_ttl,
            });

            if self.entries.len() >= self.max_entries {
                self.entries.clear();
            }
        }
    }
}
