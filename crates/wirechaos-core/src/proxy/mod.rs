pub type ProxyError = Box<dyn std::error::Error + Send + Sync>;

pub mod buffer_pool;
pub mod conn;
mod conn_read;
mod conn_write;
mod packet;
mod replication_mode;
pub mod server;
pub mod startup_config_parse_util;
pub mod auth;
