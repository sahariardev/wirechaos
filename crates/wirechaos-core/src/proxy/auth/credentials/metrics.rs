use std::sync::atomic::{AtomicU64, Ordering};

/// The three outcomes a credential lookup can have.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LookupResult {
    Hit,
    Miss,
    Unavailable,
}

#[derive(Default)]
pub struct CredentialMetrics {
    lookup_hit: AtomicU64,
    lookup_miss: AtomicU64,
    lookup_unavailable: AtomicU64,
    reload_ok: AtomicU64,
    reload_error: AtomicU64,
    generation: AtomicU64,
}

impl CredentialMetrics {
    pub fn record_lookup(&self, result: LookupResult) {
        let counter = match result {
            LookupResult::Hit => &self.lookup_hit,
            LookupResult::Miss => &self.lookup_miss,
            LookupResult::Unavailable => &self.lookup_unavailable,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_reload(&self, succeeded: bool) {
        let counter = if succeeded {
            &self.reload_ok
        } else {
            &self.reload_error
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_generation(&self, generation: u64) {
        self.generation.store(generation, Ordering::Relaxed);
    }

    /// Render every counter in the Prometheus text exposition format.
    pub fn gather(&self) -> String {
        format!(
            "# TYPE credentials_lookup_total counter\n\
             credentials_lookup_total{{result=\"hit\"}} {}\n\
             credentials_lookup_total{{result=\"miss\"}} {}\n\
             credentials_lookup_total{{result=\"unavailable\"}} {}\n\
             # TYPE credentials_reload_total counter\n\
             credentials_reload_total{{result=\"ok\"}} {}\n\
             credentials_reload_total{{result=\"error\"}} {}\n\
             # TYPE credentials_generation gauge\n\
             credentials_generation {}\n",
            self.lookup_hit.load(Ordering::Relaxed),
            self.lookup_miss.load(Ordering::Relaxed),
            self.lookup_unavailable.load(Ordering::Relaxed),
            self.reload_ok.load(Ordering::Relaxed),
            self.reload_error.load(Ordering::Relaxed),
            self.generation.load(Ordering::Relaxed),
        )
    }
}

impl std::fmt::Debug for LookupResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LookupResult::Hit => "hit",
            LookupResult::Miss => "miss",
            LookupResult::Unavailable => "unavailable",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_render_and_are_labelled_without_user_data() {
        let metrics = CredentialMetrics::default();
        metrics.record_lookup(LookupResult::Hit);
        metrics.record_lookup(LookupResult::Miss);
        metrics.record_lookup(LookupResult::Miss);
        metrics.record_lookup(LookupResult::Unavailable);
        metrics.record_reload(true);
        metrics.set_generation(3);

        let text = metrics.gather();

        assert!(text.contains("credentials_lookup_total{result=\"hit\"} 1"));
        assert!(text.contains("credentials_lookup_total{result=\"miss\"} 2"));
        assert!(text.contains("credentials_lookup_total{result=\"unavailable\"} 1"));
        assert!(text.contains("credentials_reload_total{result=\"ok\"} 1"));
        assert!(text.contains("credentials_generation 3"));
    }
}
