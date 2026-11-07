use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc,
    },
};

use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::proxy::{
    auth::credentials::CredentialStore, backend::registry::Registry, buffer_pool::MultiBufferPool,
    config::Config, conn::Conn, conn_registry::ConnRegistry, tls::FrontendTls,
};
use crate::relay::RelayConfig;

pub struct ServerConfig {
    pub bind: SocketAddr,
    pub config: Arc<Config>,
    pub credentials: CredentialStore,
    pub frontend_tls: Option<FrontendTls>,
    pub pool_min: usize,
    pub pool_max: usize,
}

pub struct ServerState {
    config: Arc<Config>,
    // 6.1: built once at startup (spec §7.3), passed to Conn in 6.13.
    #[allow(
        dead_code,
        reason = "consumed by Conn in 6.13 when Conn::handle wires relay::run"
    )]
    relay_config: Arc<RelayConfig>,
    credentials: Arc<CredentialStore>,
    frontend_tls: Option<FrontendTls>,
    pool: Arc<MultiBufferPool>,
    backends: Registry,
    connections: ConnRegistry,
    next_id: AtomicI32,
}

impl ServerState {
    #[must_use = "a server state without checking this Result is unused"]
    pub fn new(config: ServerConfig) -> anyhow::Result<Self> {
        // Validate once at startup; the relay never re-reads LimitsConfig
        // (spec §7.2/7.3). `RelayConfigError` implements `Error`, so `?`
        // carries field/value/range to the operator via `anyhow` without
        // exposing the crate-private type in this public signature.
        let relay_config = Arc::new(RelayConfig::from_config(&config.config)?);
        let connections = ConnRegistry::new(config.config.limits.max_connections);

        Ok(Self {
            config: config.config,
            relay_config,
            credentials: Arc::new(config.credentials),
            frontend_tls: config.frontend_tls,
            pool: MultiBufferPool::new(config.pool_min, config.pool_max, 16),
            backends: Registry::new(),
            connections,
            next_id: AtomicI32::new(1),
        })
    }
}

pub async fn run_server(config: ServerConfig) -> anyhow::Result<()> {
    let bind = config.bind;
    let listener = TcpListener::bind(bind).await?;
    info!(%bind, "frontend listener bound");

    serve(listener, ServerState::new(config)?).await
}

pub async fn serve(listener: TcpListener, state: ServerState) -> anyhow::Result<()> {
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                // A transient error (EMFILE, ECONNABORTED) must not kill the
                // listener: log it and keep serving.
                warn!(%error, "accept failed");
                continue;
            }
        };

        if let Err(error) = socket.set_nodelay(true) {
            warn!(%peer, %error, "failed to set TCP_NODELAY");
        }

        let conn_id = state.next_id.fetch_add(1, Ordering::Relaxed);
        let pool = Arc::clone(&state.pool);
        let backends = state.backends.clone();
        let connections = state.connections.clone();
        let credentials = Arc::clone(&state.credentials);
        let frontend_tls = state.frontend_tls.clone();
        let config = Arc::clone(&state.config);
        // 6.1: `relay_config` is held in `ServerState` for 6.13; `Conn` does
        // not consume it until `Conn::handle` wires `relay::run`, so we do
        // not clone it per-accept here yet.

        tokio::spawn(async move {
            let mut conn = Conn::new(
                conn_id,
                socket,
                pool,
                frontend_tls,
                (*credentials).clone(),
                backends,
                connections,
                config,
            );

            if let Err(error) = conn.handle().await {
                // A server-side fault: one session fails, the listener lives on.
                warn!(conn_id, %peer, "session ended with a fault: {error}");
            }
        });
    }
}
