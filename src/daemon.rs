//! Daemon mode: tails configured log files, runs the scanner pipeline,
//! and persists entries to the database until a shutdown signal arrives.
//!
//! The daemon identifies itself with a PID file so the TUI can start it
//! on demand (`ensure_daemon_running`).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
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

const DEFAULT_PID_FILE: &str = "/run/sentinel.pid";
/// Env var that overrides the PID file location (useful for tests and
/// for running without write access to `/run`).
const PID_FILE_ENV: &str = "SENTINEL_PID_FILE";

fn pid_file_path() -> PathBuf {
    std::env::var_os(PID_FILE_ENV).map_or_else(|| PathBuf::from(DEFAULT_PID_FILE), PathBuf::from)
}

/// True when a live process holds the PID file at `pid_file`.
fn is_daemon_running_at(pid_file: &Path) -> bool {
    if let Ok(pid_str) = std::fs::read_to_string(pid_file)
        && let Ok(pid) = pid_str.trim().parse::<u32>()
        && let Ok(proc_info) = process::Command::new("ps")
            .args(["-p", &pid.to_string()])
            .output()
    {
        return proc_info.status.success();
    }
    false
}

/// True when a live process holds the daemon PID file.
fn is_daemon_running() -> bool {
    is_daemon_running_at(&pid_file_path())
}

/// Command-line arguments for the daemon child process. The caller's
/// config path is forwarded so the daemon runs on the same config as
/// the TUI that started it.
fn daemon_args(config_path: &Path) -> Vec<OsString> {
    vec![
        OsString::from("--daemon"),
        OsString::from("--config"),
        config_path.as_os_str().to_os_string(),
    ]
}

/// Start the daemon (as a child process of the current executable) if it
/// is not already running, then wait until the PID file shows it alive.
pub async fn ensure_daemon_running(config_path: &Path) -> Result<(), SentinelError> {
    if is_daemon_running() {
        info!("Daemon already running");
        return Ok(());
    }

    info!("Starting daemon process");
    let mut cmd = process::Command::new(std::env::current_exe()?);
    for arg in daemon_args(config_path) {
        cmd.arg(arg);
    }

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

fn write_pid_file_at(pid_file: &Path) -> Result<(), SentinelError> {
    let pid = process::id().to_string();
    if let Some(parent) = pid_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(pid_file, pid)?;
    Ok(())
}

fn write_pid_file() -> Result<(), SentinelError> {
    write_pid_file_at(&pid_file_path())
}

fn remove_pid_file_at(pid_file: &Path) {
    let _ = std::fs::remove_file(pid_file);
}

fn remove_pid_file() {
    remove_pid_file_at(&pid_file_path());
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
    use std::path::Path;
    use tempfile::TempDir;

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

    /// The daemon child process must receive the caller's config path,
    /// otherwise a TUI started with `-c custom.yaml` would launch a
    /// daemon running on the default config.
    #[test]
    fn test_daemon_args_forward_config_path() {
        let args = daemon_args(Path::new("custom.yaml"));
        assert_eq!(args, ["--daemon", "--config", "custom.yaml"]);
    }

    #[test]
    fn test_pid_file_detects_live_process() {
        let dir = TempDir::new().unwrap();
        let pid_file = dir.path().join("sentinel.pid");

        assert!(
            !is_daemon_running_at(&pid_file),
            "no pid file -> not running"
        );

        std::fs::write(&pid_file, process::id().to_string()).unwrap();
        assert!(is_daemon_running_at(&pid_file), "own pid -> running");

        // Beyond the maximum pid on any supported OS (macOS: 99998,
        // Linux: 32768 by default), so it can never be alive.
        std::fs::write(&pid_file, "99999999").unwrap();
        assert!(!is_daemon_running_at(&pid_file), "stale pid -> not running");
    }

    #[test]
    fn test_write_and_remove_pid_file() {
        let dir = TempDir::new().unwrap();
        let pid_file = dir.path().join("nested/sentinel.pid");

        write_pid_file_at(&pid_file).expect("write creates parent dirs");
        assert_eq!(
            std::fs::read_to_string(&pid_file).unwrap(),
            process::id().to_string()
        );

        remove_pid_file_at(&pid_file);
        assert!(!pid_file.exists());
    }
}
