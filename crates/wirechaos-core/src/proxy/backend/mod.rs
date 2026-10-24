mod error;
mod pg_client;
pub mod registry;
mod scram_client;
pub mod session_key_secret;
mod timeout_stream;

use crate::proxy::backend::pg_client::PgClient;
pub use crate::proxy::backend::pg_client::PgConfig;
use crate::proxy::buffer_pool::MultiBufferPool;
use crate::proxy::error::ProxyError;
use std::collections::HashMap;
use std::sync::Arc;

pub struct Backend {
    parameters_status_values: HashMap<String, String>,
    // Kept alive for the lifetime of the backend link: the TCP/TLS stream and
    // the SCRAM state machine are not usable after the client is dropped.
    #[allow(
        dead_code,
        reason = "held for the session lifetime; dropping it closes the backend connection"
    )]
    client: PgClient,
    #[allow(
        dead_code,
        reason = "held alongside the client so the pool outlives every rented buffer"
    )]
    pool: Arc<MultiBufferPool>,
}

impl Backend {
    pub fn get_param_status_values(&self) -> Vec<(String, String)> {
        let mut params: Vec<(String, String)> = Vec::new();

        for (key, value) in &self.parameters_status_values {
            params.push((key.to_owned(), value.to_owned()));
        }

        params
    }

    pub async fn new(
        config: PgConfig,
        pool: Arc<MultiBufferPool>,
    ) -> Result<Arc<Self>, ProxyError> {
        let mut client = PgClient::connect(config, Arc::clone(&pool)).await?;
        let parameters_status_values = client.take_parameter_status_values();

        let backend = Self {
            client,
            pool,
            parameters_status_values,
        };

        Ok(Arc::new(backend))
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            client: PgClient::for_test(),
            pool: MultiBufferPool::new(16, 16, 0),
            parameters_status_values: HashMap::new(),
        }
    }
}
