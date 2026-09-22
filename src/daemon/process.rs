//! Process supervision: the daemon PID file, liveness checks, and
//! spawning the daemon as a child process of the current executable.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process;

use tracing::info;

use crate::error::SentinelError;

const DEFAULT_PID_FILE: &str = "/run/sentinel.pid";
/// Env var that overrides the PID file location (useful for tests and
/// for pinning the file to a custom path; without it, an unwritable
/// `/run` falls back to the temp dir automatically).
const PID_FILE_ENV: &str = "SENTINEL_PID_FILE";

fn pid_file_path() -> PathBuf {
    std::env::var_os(PID_FILE_ENV).map_or_else(
        || resolve_pid_file(Path::new(DEFAULT_PID_FILE)),
        PathBuf::from,
    )
}

/// Resolve the default PID file location: use `primary` when its parent
/// directory exists and is writable, otherwise fall back to a file in the
/// system temp dir. This lets unprivileged runs succeed on hosts where
/// `/run` is absent (macOS) or root-only (Linux without sudo).
fn resolve_pid_file(primary: &Path) -> PathBuf {
    let usable = primary
        .parent()
        .is_some_and(|dir| dir.is_dir() && dir_is_writable(dir));
    if usable {
        primary.to_path_buf()
    } else {
        fallback_pid_file()
    }
}

fn fallback_pid_file() -> PathBuf {
    std::env::temp_dir().join("sentinel.pid")
}

/// True when `dir` can be written to. Probed by creating and removing a
/// file so it is correct regardless of uid, ownership, or ACLs.
fn dir_is_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".sentinel-probe-{}", process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
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

pub(super) fn write_pid_file_at(pid_file: &Path) -> Result<(), SentinelError> {
    let pid = process::id().to_string();
    if let Some(parent) = pid_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(pid_file, pid)?;
    Ok(())
}

pub(super) fn write_pid_file() -> Result<(), SentinelError> {
    write_pid_file_at(&pid_file_path())
}

pub(super) fn remove_pid_file_at(pid_file: &Path) {
    let _ = std::fs::remove_file(pid_file);
}

pub(super) fn remove_pid_file() {
    remove_pid_file_at(&pid_file_path());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;

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

    /// A writable parent directory keeps the primary PID file location.
    #[test]
    fn test_resolve_pid_file_uses_primary_when_parent_writable() {
        let dir = TempDir::new().unwrap();
        let primary = dir.path().join("sentinel.pid");
        assert_eq!(resolve_pid_file(&primary), primary);
    }

    /// A missing parent directory (e.g. `/run` on macOS) must fall back
    /// to the temp dir instead of failing with Permission denied.
    #[test]
    fn test_resolve_pid_file_falls_back_when_parent_missing() {
        let primary = Path::new("/nonexistent-sentinel-test-dir/sentinel.pid");
        assert_eq!(resolve_pid_file(primary), fallback_pid_file());
    }

    /// A present but unwritable parent (e.g. root-only `/run` for an
    /// unprivileged daemon) must also fall back to the temp dir.
    #[test]
    fn test_resolve_pid_file_falls_back_when_parent_not_writable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let ro = dir.path().join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        let primary = ro.join("sentinel.pid");

        // root ignores the permission bits, so assert against the probe.
        let expected = if dir_is_writable(&ro) {
            primary.clone()
        } else {
            fallback_pid_file()
        };
        assert_eq!(resolve_pid_file(&primary), expected);

        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}
