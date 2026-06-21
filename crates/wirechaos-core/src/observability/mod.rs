use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub fn init_logging() {
    let filter_layer = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("wirechaos=info,wirechaos_core=info,warn"));

    let fmt_layer = fmt::layer()
        .with_target(true)
        .with_thread_names(true)
        .with_line_number(true)
        .with_file(false);

    let _ = tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .try_init();
}
