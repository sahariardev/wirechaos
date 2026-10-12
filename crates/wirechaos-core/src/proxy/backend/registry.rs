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

    pub fn register(
        &self,
        backend: Arc<Backend>,
        conn_id: i32,
        key_secret: SessionKeySecret,
    ) -> Result<SessionGuard, SessionKeySecret> {
        let mut inner = self.lock();

        if inner.key_secret_backend.contains_key(&key_secret) {
            return Err(key_secret);
        }

        inner.conn_backend.insert(conn_id, backend.clone());
        inner.key_secret_backend.insert(key_secret, backend);

        Ok(SessionGuard {
            registry: self.clone(),
            conn_id,
            key: key_secret,
        })
    }

    pub fn lookup_by_key(&self, key: SessionKeySecret) -> Option<Arc<Backend>> {
        self.lock().key_secret_backend.get(&key).cloned()
    }
}

pub struct SessionGuard {
    registry: Registry,
    conn_id: i32,
    key: SessionKeySecret,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let mut inner = self.registry.lock();
        if inner.conn_backend.remove(&self.conn_id).is_some() {
            inner.key_secret_backend.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SessionKeySecret {
        SessionKeySecret { key: 1, secret: 2 }
    }

    #[test]
    fn unknown_cancel_key_is_ignored_not_panicked() {
        let registry = Registry::new();
        assert!(registry.lookup_by_key(key()).is_none());
    }

    #[test]
    fn registered_key_resolves_to_its_backend() {
        let registry = Registry::new();
        let _guard = registry
            .register(Arc::new(Backend::default()), 123, key())
            .expect("first registration wins");

        assert!(registry.lookup_by_key(key()).is_some());
    }

    #[test]
    fn a_duplicate_key_is_reported_instead_of_overwriting() {
        let registry = Registry::new();
        let _first = registry
            .register(Arc::new(Backend::default()), 1, key())
            .expect("first registration wins");

        // A colliding key must be surfaced so the caller can re-mint, never
        // silently hijack the live session's cancel key.
        assert!(matches!(
            registry.register(Arc::new(Backend::default()), 2, key()),
            Err(collided) if collided == key()
        ));
    }

    #[test]
    fn the_guard_frees_the_key_on_drop() {
        let registry = Registry::new();
        let guard = registry
            .register(Arc::new(Backend::default()), 1, key())
            .expect("registration");
        assert!(registry.lookup_by_key(key()).is_some());

        drop(guard);
        assert!(registry.lookup_by_key(key()).is_none(), "key freed on drop");
    }
}
