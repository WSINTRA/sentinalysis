//! Sentinel CLI: parses flags and starts either the TUI or the daemon.

use std::path::PathBuf;
use std::process;

use clap::Parser;
use tracing::{error, info};

use sentinel::daemon::{ensure_daemon_running, run_daemon};
use sentinel::db::pool::create_pool;
use sentinel::error::SentinelError;
use sentinel::setup::{init_tracing, load_config};

#[derive(Parser, Debug)]
#[command(name = "sentinel", about = "Log monitoring and security analysis tool")]
struct Cli {
    /// Run in TUI mode (interactive terminal interface)
    #[arg(long, conflicts_with = "daemon")]
    tui: bool,

    /// Run in daemon mode (background scanning)
    #[arg(long, default_value_t = false)]
    daemon: bool,

    /// Path to configuration file
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,
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
    let pool = create_pool(&database_url).await?;

    info!(
        "Sentinel starting in {} mode",
        if cli.tui { "TUI" } else { "daemon" }
    );

    if cli.tui {
        ensure_daemon_running().await?;
        run_tui(pool).await
    } else {
        run_daemon(pool, config).await
    }
}

async fn run_tui(pool: sqlx::PgPool) -> Result<(), SentinelError> {
    info!("TUI mode starting");

    let app = sentinel::tui::app::App::new(pool);
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
