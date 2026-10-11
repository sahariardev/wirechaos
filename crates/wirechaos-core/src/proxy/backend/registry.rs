use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use crate::proxy::backend::{connection::Backend, session_key_secret::SessionKeySecret};

#[derive(Default)]
struct Inner {
    conn_backend: HashMap<i32, Arc<Backend>>,
    key_secret_backend: HashMap<SessionKeySecret, Arc<Backend>>,
}

#[derive(Clone)]
pub struct Registry {
    inner: Arc<Mutex<Inner>>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn register(&self, backend: Arc<Backend>, conn_id: i32, key_secret: SessionKeySecret) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let conn_backend = &mut inner.conn_backend;
        conn_backend.insert(conn_id, backend.clone());
        let key_secret_backend = &mut inner.key_secret_backend;
        key_secret_backend.insert(key_secret, backend);
    }

    pub fn lookup_by_key(&self, key: SessionKeySecret) -> Option<Arc<Backend>> {
        self.lock().key_secret_backend.get(&key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::backend::{registry, session_key_secret::SessionKeySecret};

    #[test]
    fn unknown_cancel_key_is_ignored_not_panicked() {
        let registry = Registry::new();
        assert!(registry
            .lookup_by_key(SessionKeySecret::default())
            .is_none())
    }

    #[test]
    fn registered_key_resolves_to_its_backend() {
        let backend = Backend::default();
        let key = SessionKeySecret::default();
        let registry = Registry::new();

        registry.register(Arc::new(backend), 123, key);
        assert!(registry.lookup_by_key(key).is_some());
    }
}
