use std::path::PathBuf;
use std::process;

use clap::Parser;
use tracing::{error, info};

use sentinel::config::Config;
use sentinel::db::pool::create_pool;
use sentinel::error::SentinelError;

mod setup;
use setup::init_tracing;
use setup::load_config;

mod daemon;
use daemon::ensure_daemon_running;
use daemon::run_daemon;

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
    init_tracing();

    let config = load_config(&cli.config)?;
    let pool = create_pool().await?;

    info!(
        "Sentinel starting in {} mode",
        if cli.tui { "TUI" } else { "daemon" }
    );

    if cli.tui {
        ensure_daemon_running().await?;
        run_tui(pool, config).await
    } else {
        run_daemon(pool, config).await
    }
}

async fn run_tui(pool: sqlx::PgPool, config: Config) -> Result<(), SentinelError> {
    info!("TUI mode starting");

    let app = sentinel::tui::app::App::new(pool, config);
    let mut tui = sentinel::tui::Tui::new()?;

    tui.run(app).await
}
