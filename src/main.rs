//! Sentinel CLI: parses flags and starts the TUI, daemon, hub, or agent;
//! `hub-key` manages hub API keys.

use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use tracing::{error, info};

use sentinel::daemon::{ensure_daemon_running, run_daemon};
use sentinel::db::pool::create_pool;
use sentinel::error::SentinelError;
use sentinel::hub::keys_cli::{HubKeyAction, run as run_hub_key};
use sentinel::setup::{init_tracing, load_config};

// One flag per mode is the documented CLI surface; a bool-per-mode is the
// clearest shape for clap here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Parser, Debug)]
#[command(name = "sentinel", about = "Log monitoring and security analysis tool")]
struct Cli {
    /// Run in TUI mode (interactive terminal interface)
    #[arg(long, conflicts_with_all = ["daemon", "hub", "agent"])]
    tui: bool,

    /// Run in daemon mode (background scanning)
    #[arg(long, default_value_t = false)]
    daemon: bool,

    /// Run in hub mode (gRPC ingestion + REST API + dashboard)
    #[arg(long, conflicts_with_all = ["daemon", "tui", "agent"])]
    hub: bool,

    /// Run in agent mode (forward metrics + logs to the hub)
    #[arg(long, conflicts_with_all = ["daemon", "tui", "hub"])]
    agent: bool,

    /// Path to configuration file
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Manage hub API keys
    HubKey {
        #[command(subcommand)]
        action: HubKeyAction,
    },
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        error!("Fatal error: {e}");
        process::exit(1);
    }
}

async fn run() -> Result<(), SentinelError> {
    let cli = Cli::parse();
    load_dotenv();
    init_tracing();

    let config = load_config(&cli.config)?;
    let database_url = std::env::var("DATABASE_URL").map_err(|_| {
        SentinelError::ConfigError("DATABASE_URL environment variable not set".into())
    })?;

    if let Some(command) = &cli.command {
        let Command::HubKey { action } = command;
        return run_hub_key(action.clone(), &database_url).await;
    }

    let pool = create_pool(&database_url).await?;

    info!(
        "Sentinel starting in {} mode",
        if cli.tui {
            "TUI"
        } else if cli.hub {
            "hub"
        } else if cli.agent {
            "agent"
        } else {
            "daemon"
        }
    );

    if cli.tui {
        ensure_daemon_running(&cli.config).await?;
        run_tui(pool, &config).await
    } else if cli.hub {
        sentinel::hub::run_hub::run(pool, config).await
    } else if cli.agent {
        sentinel::agent::run(config).await
    } else {
        run_daemon(pool, config).await
    }
}

async fn run_tui(
    pool: sqlx::PgPool,
    config: &sentinel::config::Config,
) -> Result<(), SentinelError> {
    info!("TUI mode starting");

    // The TUI lists the same sources the daemon tails, from the config.
    let discovery =
        sentinel::log_scanner::source_discovery::SourceDiscovery::from_config(&config.log_watching);
    let data_source = sentinel::tui::data::pg::PgLogDataSource::new(pool, discovery);

    let app = sentinel::tui::app::App::new(data_source);
    let mut tui = sentinel::tui::Tui::new()?;

    tui.run(app).await
}

fn load_dotenv() {
    if let Err(e) = dotenvy::from_filename(".env")
        && !matches!(e, dotenvy::Error::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound)
    {
        eprintln!("Warning: failed to load .env: {e}");
    }
}
