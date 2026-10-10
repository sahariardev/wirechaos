use std::sync::{Arc, PoisonError, RwLock};

pub const MAX_CONCURRENT_CONNECCTION: u32 = 100;

//todo:: think about locking in future
pub struct ConnRegistry {
    inner: Arc<RwLock<Inner>>,
}

struct Inner {
    total_concurrent_connection_count: u32,
}

impl ConnRegistry {
    pub fn get_concurrent_connection_count(&self) -> u32 {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .total_concurrent_connection_count
    }
}
