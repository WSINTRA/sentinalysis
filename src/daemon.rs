use sentinel::config::Config;
use sentinel::db::repositories::log_entry_repo::LogEntryRepository;
use sentinel::db::repositories::service_repo::ServiceRepository;
use sentinel::error::SentinelError;
use sentinel::log_scanner::classifier::Classifier;
use sentinel::log_scanner::filter::NoiseFilter;
use sentinel::log_scanner::pipeline::{DbServiceResolver, ParserRegistry, Pipeline};
use sentinel::log_scanner::scanner::{RepositorySink, Scanner};
use sentinel::log_scanner::tailer::FileTailer;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
const PID_FILE: &str = "/run/sentinel.pid";
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
async fn daemon_loop(
    pool: sqlx::PgPool,
    config: Config,
    _cancel: CancellationToken,
) -> Result<(), SentinelError> {
    info!("Daemon loop starting");

    let log_repo = LogEntryRepository::new(pool.clone());
    let pipeline = Arc::new(Pipeline::new(
        ParserRegistry::default_registry(),
        Arc::new(NoiseFilter::new()),
        Arc::new(Classifier::new()),
        Arc::new(DbServiceResolver::new(ServiceRepository::new(pool))),
    ));

    let mut tailer = FileTailer::new();

    for dir_config in &config.log_watching.directories {
        tailer = tailer.with_watch_directory(dir_config.path.clone(), &dir_config.pattern)?;
    }

    if !config.log_watching.files.is_empty() {
        tailer = tailer.with_files(config.log_watching.files.clone());
    }

    let rx = tailer.start().await?;
    info!("File tailer started, watching logs");

    Scanner::new(pipeline)
        .run(rx, &RepositorySink::new(&log_repo))
        .await?;

    Ok(())
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
pub async fn run_daemon(pool: sqlx::PgPool, config: Config) -> Result<(), SentinelError> {
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
