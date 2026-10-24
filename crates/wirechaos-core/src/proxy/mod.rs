pub type InternalError = Box<dyn std::error::Error + Send + Sync>;

pub mod auth;
pub mod backend;
pub mod buffer_pool;
pub mod config;
pub mod conn;
mod conn_read;
pub mod conn_registry;
mod conn_write;
pub mod error;
mod packet;
mod replication_mode;
pub mod server;
pub mod startup_config_parse_util;
pub mod tls;
mod wire_util;
