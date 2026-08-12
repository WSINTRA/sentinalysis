use std::path::{Path, PathBuf};
use std::process;

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use sentinel::config::Config;
use sentinel::db::pool::create_pool;
use sentinel::error::SentinelError;

const PID_FILE: &str = "/run/sentinel.pid";

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

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sentinel=info".parse().unwrap()),
        )
        .with_target(false)
        .init();
}

fn load_config(path: &Path) -> Result<Config, SentinelError> {
    if path.exists() {
        Config::load(path.to_str().unwrap())
    } else {
        info!("Config file not found at '{}', using defaults", path.display());
        Ok(Config::default_config())
    }
}

async fn ensure_daemon_running() -> Result<(), SentinelError> {
    if is_daemon_running() {
        info!("Daemon already running");
        return Ok(());
    }

    info!("Starting daemon process");
    let mut cmd = process::Command::new(std::env::current_exe()?);
    cmd.arg("--daemon");

    match cmd.spawn() {
        Ok(_) => {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            if !is_daemon_running() {
                return Err(SentinelError::ServiceError(
                    "Daemon failed to start".into(),
                ));
            }
            info!("Daemon started");
        }
        Err(e) => {
            return Err(SentinelError::ServiceError(format!(
                "Failed to start daemon: {e}"
            )));
        }
    }

    Ok(())
}

fn is_daemon_running() -> bool {
    if let Ok(pid_str) = std::fs::read_to_string(PID_FILE)
        && let Ok(pid) = pid_str.trim().parse::<u32>()
        && let Ok(proc_info) = process::Command::new("ps")
            .args(["-p", &pid.to_string()])
            .output()
    {
        return proc_info.status.success();
    }
    false
}

async fn run_daemon(pool: sqlx::PgPool, config: Config) -> Result<(), SentinelError> {
    write_pid_file()?;
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let handle = tokio::spawn(async move {
        if let Err(e) = daemon_loop(pool, config, cancel_clone).await {
            error!("Daemon error: {e}");
        }
    });

    tokio::select! {
        () = wait_for_shutdown() => {
            info!("Shutdown signal received");
            cancel.cancel();
        }
        result = handle => {
            if let Err(e) = result {
                error!("Daemon task panicked: {e}");
            }
        }
    }

    remove_pid_file();
    info!("Daemon stopped");
    Ok(())
}

async fn daemon_loop(
    pool: sqlx::PgPool,
    config: Config,
    _cancel: CancellationToken,
) -> Result<(), SentinelError> {
    info!("Daemon loop starting");

    let scanner = sentinel::log_scanner::scanner::Scanner::new(pool);
    let mut tailer = sentinel::log_scanner::tailer::FileTailer::new();

    for dir_config in &config.log_watching.directories {
        tailer = tailer.with_watch_directory(dir_config.path.clone(), &dir_config.pattern);
    }

    if !config.log_watching.files.is_empty() {
        tailer = tailer.with_files(config.log_watching.files.clone());
    }

    let rx = tailer.start().await?;
    info!("File tailer started, watching logs");

    scanner.run(rx).await?;

    Ok(())
}

async fn run_tui(pool: sqlx::PgPool, config: Config) -> Result<(), SentinelError> {
    info!("TUI mode starting");

    let app = sentinel::tui::app::App::new(pool, config);
    let mut tui = sentinel::tui::Tui::new()?;

    tui.run(app).await
}

fn write_pid_file() -> Result<(), SentinelError> {
    let pid = process::id().to_string();
    if let Some(parent) = PathBuf::from(PID_FILE).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(PID_FILE, pid)?;
    Ok(())
}

fn remove_pid_file() {
    let _ = std::fs::remove_file(PID_FILE);
}

async fn wait_for_shutdown() {
    let mut sigint =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();

    tokio::select! {
        _ = sigint.recv() => {},
        _ = sigterm.recv() => {},
    }
}
