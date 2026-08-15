//! Daemon execution: build the tailer from the config, run the scanner
//! pipeline until a shutdown signal, and maintain the PID file.

use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::config::Config;
use crate::daemon::process::{remove_pid_file, write_pid_file};
use crate::db::repositories::log_entry_repo::LogEntryRepository;
use crate::error::SentinelError;
use crate::log_scanner::pipeline::build_pipeline;
use crate::log_scanner::scanner::{BATCH_INTERVAL, BATCH_SIZE, RepositorySink, Scanner};
use crate::log_scanner::tailer::FileTailer;

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
    /// Building the tailer must not require a tokio runtime.
    #[test]
    fn test_build_tailer_accepts_empty_config() {
        let mut config = Config::default();
        config.log_watching.directories.clear();
        config.log_watching.files.clear();
        let tailer = build_tailer(&config).expect("empty watch list builds a tailer");
        let _ = tailer;
    }
}
