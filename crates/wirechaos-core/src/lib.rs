mod observability;
pub mod proxy;

pub fn init_core() {
    observability::init_logging();
    tracing::info!("Core infrastructure and logging initialized.");
}