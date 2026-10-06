use std::{error::Error, time::Duration};

use crate::proxy::auth::{
    credentials::cache::{self, TtlCache},
    verifier::{ProviderError, Verifier},
};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tokio_postgres::{Client, NoTls};
use zeroize::Zeroizing;

pub struct AuthQueryConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Zeroizing<String>,
    pub query: String,
    pub database: String,
    pub cache_ttl: Duration,
}

impl AuthQueryConfig {
    pub fn validate(query: &str) -> Result<(), &'static str> {
        let count = query.matches("$1").count();
        if count == 1 {
            Ok(())
        } else {
            Err("query must contain exatly one $1")
        }
    }
}

pub struct AuthQuerySource {
    pub config: AuthQueryConfig,
    pub cache: Mutex<TtlCache>,
    pub client: Mutex<Option<Client>>,
}

impl AuthQuerySource {
    pub async fn lookup(&self, username: &str) -> Result<Option<Arc<Verifier>>, ProviderError> {
        let now = Instant::now();
        if let Some(cached) = self.cache.lock().await.get(username, now) {
            return Ok(cached);
        }

        let row = self
            .query_backend(username)
            .await
            .map_err(|err| ProviderError::Unavailable(Box::new(err)))?;

        let mut cache = self.cache.lock().await;

        match row {
            Some(secret) => {
                let verifier = Verifier::from_pg_secret(&secret)
                    .map_err(|err| ProviderError::Unavailable(Box::new(err)))?;

                let verifier = Arc::new(verifier);

                cache.add_positive_entry(username, verifier.clone(), now);
                Ok(Some(verifier))
            }
            None => {
                cache.add_negative_entry(username, now);
                Ok(None)
            }
        }
    }

    async fn query_backend(&self, username: &str) -> Result<Option<String>, tokio_postgres::Error> {
        let mut guard = self.client.lock().await;

        if guard.is_none() {
            let (client, connection) =
                tokio_postgres::connect(&self.connecting_string(), NoTls).await?;
            tokio::spawn(connection);

            *guard = Some(client);
        }

        let client = guard.as_ref().expect("just set");
        let row = client.query_opt(&self.config.query, &[&username]).await?;
        Ok(row.map(|row| row.get::<_, String>(1)))
    }

    fn connecting_string(&self) -> String {
        todo!("implemnt this")
    }
}
