use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "wirechaos")]
#[command(about = "A chaotic wire-level proxy for network testing", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the chaos proxy server
    Proxy,
    /// Run a specific testing scenario
    Scenario,
    /// Check system dependencies and environment health
    Doctor,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Initialize tracing so we can see info logs in the terminal
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // 2. Call your library's Hello World function here!
    wirechaos_core::init_core();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Proxy => {
            tracing::info!("Starting proxy mode...");
        }
        Commands::Scenario => {
            tracing::info!("Running chaos scenario...");
        }
        Commands::Doctor => {
            tracing::info!("Running environment diagnostic check...");
        }
    }

    Ok(())
}