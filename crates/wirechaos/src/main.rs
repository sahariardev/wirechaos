use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use zeroize::Zeroizing;

use wirechaos_core::proxy::auth::credentials::hash_password;
use wirechaos_core::proxy::auth::verifier::MIN_ITERATIONS;

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
    /// Derive a PostgreSQL SCRAM-SHA-256 secret from a password
    ///
    /// The output can be pasted into `pg_authid.rolpassword` / `ALTER ROLE …
    /// PASSWORD …` and into a `wirechaos` `users.yaml` `scram_secret:` entry.
    HashPassword {
        /// PBKDF2 iteration count (PostgreSQL's `scram_sha_256_iterations`).
        #[arg(long, default_value_t = 4096)]
        iterations: u32,
        /// Output shape.
        #[arg(long, value_enum, default_value_t = HashFormat::Secret)]
        format: HashFormat,
        /// User name; required by `--format=yaml-snippet`.
        #[arg(long)]
        user: Option<String>,
        /// Read the password as one line from stdin instead of prompting.
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum HashFormat {
    /// `SCRAM-SHA-256$iterations:salt$stored:server`
    Secret,
    /// A ready-to-paste `users.yaml` entry.
    YamlSnippet,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // The `hash-password` output is meant to be piped, so it must not share
    // stdout with a log banner.
    if !matches!(cli.command, Commands::HashPassword { .. }) {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();

        wirechaos_core::init_core();
    }

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
        Commands::HashPassword {
            iterations,
            format,
            user,
            password_stdin,
        } => {
            if *iterations < MIN_ITERATIONS {
                anyhow::bail!("--iterations must be at least {MIN_ITERATIONS}");
            }

            let password = read_password(*password_stdin)?;
            if password.is_empty() {
                anyhow::bail!("the password must not be empty");
            }

            let secret = hash_password(&password, *iterations);

            match format {
                HashFormat::Secret => println!("{secret}"),
                HashFormat::YamlSnippet => {
                    let user = user.as_deref().ok_or_else(|| {
                        anyhow::anyhow!("--user is required with --format=yaml-snippet")
                    })?;
                    println!("users:\n  - name: {user}\n    scram_secret: \"{secret}\"");
                }
            }
        }
    }

    Ok(())
}

fn read_password(from_stdin: bool) -> anyhow::Result<Zeroizing<String>> {
    if from_stdin {
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)?;
        return Ok(Zeroizing::new(
            line.trim_end_matches(['\r', '\n']).to_owned(),
        ));
    }

    let password = rpassword::prompt_password("Password: ")?;
    let confirmation = rpassword::prompt_password("Confirm password: ")?;

    if password != confirmation {
        anyhow::bail!("passwords do not match");
    }

    Ok(Zeroizing::new(password))
}
