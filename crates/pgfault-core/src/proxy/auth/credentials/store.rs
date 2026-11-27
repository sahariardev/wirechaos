use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use zeroize::Zeroizing;

#[cfg(feature = "auth-query")]
use crate::proxy::auth::credentials::auth_query::AuthQuerySource;
use crate::proxy::auth::{
    credentials::{
        file::snapshot_from_yaml,
        metrics::{CredentialMetrics, LookupResult},
        report::ConfigError,
        secret::derive_verifier,
    },
    verifier::{ProviderError, Verifier, VerifierProvider},
};

/// Where a store's verifiers come from.
pub enum Source {
    /// A YAML user list re-read on reload.
    File(PathBuf),
    /// A snapshot built in memory (tests, `with_password`). Not reloadable.
    Memory,
    /// A store that is deliberately broken, for outage-path tests.
    Failing(String),
    /// A pgbouncer-style lookup query. Boxed to keep the enum small.
    #[cfg(feature = "auth-query")]
    AuthQuery(Box<AuthQuerySource>),
}

/// One immutable generation of the user→verifier map.
pub struct Snapshot {
    generation: u64,
    users: HashMap<String, Arc<Verifier>>,
}

impl Snapshot {
    pub fn new(generation: u64, users: HashMap<String, Arc<Verifier>>) -> Self {
        Self { generation, users }
    }

    pub fn empty(generation: u64) -> Self {
        Self::new(generation, HashMap::new())
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn get(&self, username: &str) -> Option<Arc<Verifier>> {
        self.users.get(username).cloned()
    }

    pub fn len(&self) -> usize {
        self.users.len()
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    pub(crate) fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }
}

struct Inner {
    source: Source,
    snapshot: ArcSwap<Snapshot>,
    cluster_nonce: [u8; 32],
    last_loading_error: Mutex<Option<Arc<ConfigError>>>,
    metrics: CredentialMetrics,
}

pub struct CredentialStore {
    inner: Arc<Inner>,
}

impl Clone for CredentialStore {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// The outcome of a successful reload.
pub struct ReloadReport {
    pub user_count: usize,
    pub previous_generation: u64,
}

/// A cheap, cloneable handle to the same store, used by the SIGHUP/API reload
/// paths without handing out the store itself.
#[derive(Clone)]
pub struct ReloadHandle {
    inner: Arc<Inner>,
}

impl ReloadHandle {
    pub fn reload(&self) -> Result<ReloadReport, ConfigError> {
        reload_inner(&self.inner)
    }

    pub fn last_reload_error(&self) -> Option<Arc<ConfigError>> {
        lock_unpoisoned(&self.inner.last_loading_error).clone()
    }
}

impl VerifierProvider for CredentialStore {
    async fn lookup(&self, username: &str) -> Result<Option<Arc<Verifier>>, ProviderError> {
        let result = match &self.inner.source {
            Source::File(_) | Source::Memory => Ok(self.inner.snapshot.load().get(username)),
            Source::Failing(reason) => Err(ProviderError::Unavailable(reason.clone().into())),
            #[cfg(feature = "auth-query")]
            Source::AuthQuery(source) => source.lookup(username).await,
        };

        self.inner.metrics.record_lookup(match &result {
            Ok(Some(_)) => LookupResult::Hit,
            Ok(None) => LookupResult::Miss,
            Err(_) => LookupResult::Unavailable,
        });

        result
    }

    fn get_dummy_verifier(&self, username: &str) -> Verifier {
        Verifier::dummy(username, &self.inner.cluster_nonce)
    }
}

impl CredentialStore {
    /// Build a store from an in-memory YAML user list.
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        let snapshot = snapshot_from_yaml(text)?;
        Ok(Self::from_source(Source::Memory, snapshot))
    }

    /// Build a store backed by a YAML file, retaining the path for reload.
    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self, ConfigError> {
        let path = path.into();
        let text = read_file(&path)?;
        let snapshot = snapshot_from_yaml(&text)?;
        Ok(Self::from_source(Source::File(path), snapshot))
    }

    /// A store that knows exactly one user by plaintext password. Intended for
    /// tests and for programmatic embedding.
    pub fn with_password(user: &str, password: &str) -> Self {
        let mut users = HashMap::new();
        users.insert(
            user.to_owned(),
            Arc::new(derive_verifier(
                password,
                &rand::random::<[u8; 16]>(),
                crate::proxy::auth::credentials::file::DEFAULT_ITERATIONS,
            )),
        );

        Self::from_source(Source::Memory, Snapshot::new(1, users))
    }

    /// A store that fails every lookup with [`ProviderError::Unavailable`].
    pub fn failing(reason: impl Into<String>) -> Self {
        Self::from_source(Source::Failing(reason.into()), Snapshot::empty(1))
    }

    /// Build a store from an arbitrary source and snapshot.
    pub fn from_source(source: Source, mut snapshot: Snapshot) -> Self {
        if snapshot.generation() == 0 {
            snapshot.set_generation(1);
        }

        let metrics = CredentialMetrics::default();
        metrics.set_generation(snapshot.generation());

        Self {
            inner: Arc::new(Inner {
                source,
                snapshot: ArcSwap::from_pointee(snapshot),
                cluster_nonce: rand::random(),
                last_loading_error: Mutex::new(None),
                metrics,
            }),
        }
    }

    /// A handle that can trigger and report reloads on this store.
    pub fn reload_handle(&self) -> ReloadHandle {
        ReloadHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Re-read the backing file and atomically replace the snapshot.
    pub fn reload(&self) -> Result<ReloadReport, ConfigError> {
        reload_inner(&self.inner)
    }

    pub fn last_reload_error(&self) -> Option<Arc<ConfigError>> {
        self.reload_handle().last_reload_error()
    }

    pub fn len(&self) -> usize {
        self.inner.snapshot.load().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.snapshot.load().is_empty()
    }

    pub fn generation(&self) -> u64 {
        self.inner.snapshot.load().generation()
    }

    /// Render the store's counters for the `/metrics` endpoint.
    pub fn collect_metrics(&self) -> String {
        self.inner.metrics.gather()
    }
}

fn reload_inner(inner: &Inner) -> Result<ReloadReport, ConfigError> {
    let result = match &inner.source {
        Source::File(path) => reload_file(inner, path),
        Source::Memory => Err(ConfigError::single(
            "memory",
            "in-memory store cannot reload",
        )),
        Source::Failing(_) => Err(ConfigError::single("source", "failing store cannot reload")),
        #[cfg(feature = "auth-query")]
        Source::AuthQuery(_) => Err(ConfigError::single(
            "auth_query",
            "auth_query store has no on-disk snapshot to reload",
        )),
    };

    inner.metrics.record_reload(result.is_ok());
    if let Ok(report) = &result {
        inner.metrics.set_generation(report.previous_generation + 1);
    }

    result
}

fn reload_file(inner: &Inner, path: &std::path::Path) -> Result<ReloadReport, ConfigError> {
    let text = match read_file(path) {
        Ok(text) => text,
        Err(error) => {
            record_load_error(inner, error.clone());
            return Err(error);
        }
    };

    let mut next = match snapshot_from_yaml(&text) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            record_load_error(inner, error.clone());
            return Err(error);
        }
    };

    let previous = inner.snapshot.load_full();
    next.set_generation(previous.generation() + 1);

    let previous_generation = previous.generation();
    inner.snapshot.store(Arc::new(next));
    *lock_unpoisoned(&inner.last_loading_error) = None;

    Ok(ReloadReport {
        user_count: inner.snapshot.load().len(),
        previous_generation,
    })
}

fn record_load_error(inner: &Inner, error: ConfigError) {
    *lock_unpoisoned(&inner.last_loading_error) = Some(Arc::new(error));
}

/// Lock a mutex and recover the data even if a previous holder panicked.
///
/// A poisoned credential mutex is not a reason to abort an authentication
/// request, and `expect`/`unwrap` are denied in production code, so the poison
/// is deliberately discarded.
fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn read_file(path: &std::path::Path) -> Result<Zeroizing<String>, ConfigError> {
    std::fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|_| ConfigError::single("path", "unable to read the credentials file"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(CredentialStore: std::fmt::Debug, std::fmt::Display);

    #[tokio::test]
    async fn accepts_either_password_or_secret_per_user() {
        let derived = Verifier::from_password("bob-password", [7u8; 16], 4096);
        let yaml = format!(
            "users:\n  \
             - name: alice\n    password: \"s3cret\"\n  \
             - name: bob\n    scram_secret: \"{}\"\n",
            derived.to_pg_secret()
        );

        let store = CredentialStore::from_yaml(&yaml).expect("valid store");
        assert_eq!(store.len(), 2);
        assert!(store.lookup("alice").await.unwrap().is_some());

        let bob = store.lookup("bob").await.unwrap().expect("bob is present");
        assert_eq!(bob.stored_key(), derived.stored_key());
        assert_eq!(bob.salt(), derived.salt());
    }

    #[tokio::test]
    async fn reports_every_invalid_entry_not_just_the_first() {
        let yaml = r#"
users:
  - name: alice
    password: ""
  - name: alice
    password: "duplicate name"
  - name: carol
    password: "x"
    scram_secret: "SCRAM-SHA-256$4096:c2FsdA==$AA:BB"
  - name: dave
    scram_secret: "SCRAM-SHA-256$1:c2FsdA==$AA:BB"
"#;

        let report = CredentialStore::from_yaml(yaml)
            .err()
            .expect("invalid store must be rejected")
            .to_string();

        assert!(
            report.contains("alice"),
            "empty password + duplicate: {report}"
        );
        assert!(
            report.contains("carol"),
            "both password and secret: {report}"
        );
        assert!(report.contains("dave"), "iterations below 4096: {report}");
        assert!(
            !report.contains("duplicate name"),
            "values must not be echoed: {report}"
        );
    }

    #[tokio::test]
    async fn md5_secrets_are_rejected_with_a_reason() {
        let yaml = "\
users:
  - name: legacy
    scram_secret: \"md5a1b2c3d4e5f60718293a4b5c6d7e8f9\"
";
        let report = CredentialStore::from_yaml(yaml)
            .err()
            .expect("md5 must be rejected")
            .to_string();

        assert!(
            report.contains("MD5"),
            "the error must explain the format: {report}"
        );
        assert!(report.contains("not supported"), "{report}");
    }

    #[test]
    fn hash_password_output_round_trips() {
        let secret = crate::proxy::auth::credentials::hash_password("pencil", 4096);
        let parsed = Verifier::from_pg_secret(&secret).expect("our own output must parse");

        assert_eq!(parsed.iterations(), 4096);
        assert_eq!(parsed.stored_key().len(), 32);
        assert!(secret.starts_with("SCRAM-SHA-256$4096:"));
        // Guard against accidentally embedding the plaintext in the output.
        assert!(!secret.contains("pencil"));
    }

    #[tokio::test]
    async fn metrics_are_counted_without_user_labels() {
        let store = CredentialStore::from_yaml("users:\n  - name: alice\n    password: \"pw\"\n")
            .expect("valid store");

        let _ = store.lookup("alice").await.expect("hit");
        let _ = store.lookup("ghost").await.expect("miss");

        let metrics = store.collect_metrics();
        assert!(
            metrics.contains("credentials_lookup_total{result=\"hit\"} 1"),
            "{metrics}"
        );
        assert!(
            metrics.contains("credentials_lookup_total{result=\"miss\"} 1"),
            "{metrics}"
        );
        assert!(
            !metrics.contains("alice"),
            "metrics must not carry user labels"
        );
    }
}
