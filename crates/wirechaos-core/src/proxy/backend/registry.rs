use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
};

use crate::proxy::backend::{connection::Backend, session_key_secret::SessionKeySecret};

struct Inner {
    conn_backend: HashMap<i32, Arc<Backend>>,
    key_secret_backend: HashMap<SessionKeySecret, Arc<Backend>>,
}

#[derive(Clone)]
pub struct Registry {
    inner: Arc<Mutex<Inner>>,
}

impl Registry {
    pub fn register(&self, backend: Arc<Backend>, conn_id: i32, key_secret: SessionKeySecret) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let conn_backend = &mut inner.conn_backend;
        conn_backend.insert(conn_id, backend.clone());
        let key_secret_backend = &mut inner.key_secret_backend;
        key_secret_backend.insert(key_secret, backend);
    }

    #[allow(clippy::todo)]
    pub fn cancel_request(&self, key_secret: SessionKeySecret) {
        todo!("implement later on")
    }
}
