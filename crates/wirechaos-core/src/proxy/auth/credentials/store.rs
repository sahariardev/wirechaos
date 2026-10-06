use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::proxy::auth::credentials::{auth_query::AuthQuerySource, file::snapshot_from_yaml};
use arc_swap::ArcSwap;

use crate::proxy::auth::{
    credentials::report::ConfigError,
    verifier::{Verifier, VerifierProvider},
};

pub enum Source {
    FILE(std::path::PathBuf),
    MEMORY,
    #[cfg(feature = "auth-query")]
    AUTH_QUERY(AuthQuerySource),
}

pub struct Snapshot {
    generation: u64,
    users: HashMap<String, Arc<Verifier>>,
}

impl Snapshot {
    pub fn get(&self, username: &str) -> Option<Arc<Verifier>> {
        self.users.get(username).cloned()
    }

    pub fn new(generation: u64, users: HashMap<String, Arc<Verifier>>) -> Self {
        Self { generation, users }
    }
}

pub struct Inner {
    source: Source,
    snapshot: ArcSwap<Snapshot>,
    cluster_noce: [u8; 32],
    last_loading_error: std::sync::Mutex<Option<Arc<ConfigError>>>,
}

pub struct CredentialStore {
    inner: Arc<Inner>,
}

pub struct ReloadReport {
    pub user_count: usize,
    pub previous_generation: u64,
}

impl VerifierProvider for CredentialStore {
    async fn lookup(
        &self,
        username: &str,
    ) -> Result<Option<Arc<Verifier>>, crate::proxy::auth::verifier::ProviderError> {
        match self.inner.source {
            Source::FILE(_) | Source::MEMORY => Ok(self.inner.snapshot.load().get(username)),
        }
    }

    fn get_dummy_verifier(&self, username: &str) -> Verifier {
        Verifier::dummy(username, &self.inner.cluster_noce)
    }
}

impl CredentialStore {
    pub fn reload(&self) -> Result<ReloadReport, ConfigError> {
        match &self.inner.source {
            Source::FILE(path) => {
                let text = std::fs::read_to_string(path)
                    .map_err(|_| ConfigError::single("path", "Unable to load from path"))?;
                let next_snapshot = snapshot_from_yaml(&text)?;
                let previous_snapshot = self.inner.snapshot.swap(Arc::new(next_snapshot));
                *self.inner.last_loading_error.lock().expect("not poisoned") = None;
                Ok(ReloadReport {
                    user_count: self.inner.snapshot.load().users.len(),
                    previous_generation: previous_snapshot.generation,
                })
            }
            Source::MEMORY => Err(ConfigError::single(
                "memory",
                "inMemory store cannot reload",
            )),
        }
    }

    pub fn last_reload_error(&self) -> Option<Arc<ConfigError>> {
        self.inner
            .last_loading_error
            .lock()
            .expect("not poisoned")
            .clone()
    }

    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        let snapshot = snapshot_from_yaml(text)?;
        Ok(Self::from_source(Source::MEMORY, snapshot))
    }

    pub fn from_file(path: impl Into<std::path::PathBuf>) -> Result<Self, ConfigError> {
        let path = path.into();
        let text = std::fs::read_to_string(&path)
            .map_err(|_| ConfigError::single("path", "error loading from path"))?;
        let snapshot = snapshot_from_yaml(&text)?;
        Ok(Self::from_source(Source::FILE(path), snapshot))
    }

    pub fn from_source(source: Source, snapshot: Snapshot) -> Self {
        Self {
            inner: Arc::new(Inner {
                source,
                snapshot: ArcSwap::from_pointee(snapshot),
                cluster_noce: rand::random(),
                last_loading_error: Mutex::new(None),
            }),
        }
    }
}
