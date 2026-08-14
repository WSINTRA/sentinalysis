//! Daemon mode: tails configured log files, runs the scanner pipeline,
//! and persists entries to the database until a shutdown signal arrives.
//!
//! The daemon identifies itself with a PID file so the TUI can start it
//! on demand (`ensure_daemon_running`).

use std::path::PathBuf;
use std::process;

use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::config::Config;
use crate::db::repositories::log_entry_repo::LogEntryRepository;
use crate::error::SentinelError;
use crate::log_scanner::pipeline::build_pipeline;
use crate::log_scanner::scanner::{BATCH_INTERVAL, BATCH_SIZE, RepositorySink, Scanner};
use crate::log_scanner::tailer::FileTailer;

const PID_FILE: &str = "/run/sentinel.pid";

/// True when a live process holds the daemon PID file.
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

/// Start the daemon (as a child process of the current executable) if it
/// is not already running, then wait until the PID file shows it alive.
pub async fn ensure_daemon_running() -> Result<(), SentinelError> {
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
                return Err(SentinelError::ServiceError("Daemon failed to start".into()));
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

/// Build the tailer from the configured watch targets.
fn build_tailer(config: &Config) -> Result<FileTailer, SentinelError> {
    let mut tailer = FileTailer::new();

    for dir_config in &config.log_watching.directories {
        tailer = tailer.with_watch_directory(dir_config.path.clone(), &dir_config.pattern)?;
    }

    if !config.log_watching.files.is_empty() {
        tailer = tailer.with_files(config.log_watching.files.clone());
    }

    Ok(tailer)
}

/// Tail the configured logs and feed them through the scanner until
/// `cancel` fires or the tailer stream ends.
async fn daemon_loop(
    pool: PgPool,
    config: Config,
    cancel: CancellationToken,
) -> Result<(), SentinelError> {
    info!("Daemon loop starting");

    let log_repo = LogEntryRepository::new(pool.clone());
    let pipeline = build_pipeline(pool, &config.noise_filter);

    let rx = build_tailer(&config)?.start().await?;
    info!("File tailer started, watching logs");

    let scanner = Scanner::with_cancel(pipeline, BATCH_SIZE, Some(BATCH_INTERVAL), cancel);
    scanner.run(rx, &RepositorySink::new(&log_repo)).await
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

async fn wait_for_shutdown() -> Result<(), SentinelError> {
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|e| {
            SentinelError::ServiceError(format!("failed to register SIGINT handler: {e}"))
        })?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| {
            SentinelError::ServiceError(format!("failed to register SIGTERM handler: {e}"))
        })?;

    tokio::select! {
        _ = sigint.recv() => {},
        _ = sigterm.recv() => {},
    }
    Ok(())
}

/// Run the daemon: write the PID file, scan until a shutdown signal (or
/// a fatal scan error), then clean up the PID file.
pub async fn run_daemon(pool: PgPool, config: Config) -> Result<(), SentinelError> {
    write_pid_file()?;
    let cancel = CancellationToken::new();

    let handle = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            if let Err(e) = daemon_loop(pool, config, cancel).await {
                error!("Daemon error: {e}");
            }
        }
    });

    tokio::select! {
        result = wait_for_shutdown() => {
            if let Err(e) = result {
                error!("{e}");
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    /// The default config must build a tailer, and an empty watch list
    /// must be tolerated (a tailer with no targets is still valid).
    /// `FileTailer` captures the current runtime handle, hence
    /// `#[tokio::test]`.
    #[tokio::test]
    async fn test_build_tailer_accepts_empty_config() {
        let mut config = Config::default();
        config.log_watching.directories.clear();
        config.log_watching.files.clear();
        let tailer = build_tailer(&config).expect("empty watch list builds a tailer");
        let _ = tailer;
    }
}
