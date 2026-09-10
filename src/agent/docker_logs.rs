//! Docker container-log tailing without the docker CLI.
//!
//! Discovery reads `/var/lib/docker/containers/*/config.v2.json` (fields
//! `Name` and `LogPath`); tailing reuses the `notify` watcher pattern from
//! `log_scanner::tailer` but seeks to END-OF-FILE at startup so only logs
//! written after the agent starts are forwarded. No shell-out, no docker
//! group membership — read-only ACL access to the container tree suffices.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

use notify::{Event, Watcher, recommended_watcher};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Default Docker container-log root.
pub const DEFAULT_DOCKER_ROOT: &str = "/var/lib/docker/containers";

/// A parsed Docker JSON log envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct DockerLogLine {
    pub timestamp_ms: i64,
    pub container: String,
    pub stream: String,
    pub message: String,
}

/// `config.v2.json` — only the fields we need.
#[derive(Debug, Deserialize)]
struct ContainerConfigV2 {
    name: Option<String>,
    log_path: Option<String>,
}

/// A container being tailed.
#[derive(Debug)]
struct Tailed {
    name: String,
    log_path: PathBuf,
    offset: u64,
}

/// Discovers containers matching `names` under `root`.
///
/// # Errors
/// I/O failure when the root directory is unreadable.
fn discover(root: &Path, names: &[String]) -> Result<Vec<Tailed>, std::io::Error> {
    let mut tailed = Vec::new();
    if names.is_empty() {
        return Ok(tailed);
    }
    for entry in std::fs::read_dir(root)? {
        let Ok(entry) = entry else { continue };
        let dir = entry.path();
        let Ok(config_raw) = std::fs::read(dir.join("config.v2.json")) else {
            continue;
        };
        let Ok(config) = serde_json::from_slice::<ContainerConfigV2>(&config_raw) else {
            tracing::debug!(dir = %dir.display(), "unreadable container config; skipping");
            continue;
        };
        // Names in config.v2.json carry a leading slash.
        let name = config.name.unwrap_or_default();
        let short = name.trim_start_matches('/');
        if !names.iter().any(|wanted| wanted == short) {
            continue;
        }
        let Some(log_path) = config.log_path else {
            tracing::warn!(container = %short, "container has no log path; skipping");
            continue;
        };
        let offset = std::fs::metadata(&log_path).map_or(0, |meta| meta.len());
        tracing::info!(container = %short, from_offset = offset, "tailing container");
        tailed.push(Tailed {
            name: short.to_string(),
            log_path: PathBuf::from(log_path),
            offset,
        });
    }
    Ok(tailed)
}

/// Tail the discovered containers: `notify` watches for modifications, new
/// bytes after the saved offset are parsed as Docker JSON envelopes.
///
/// Returns the tokio receiver of parsed lines; runs until `cancel`.
///
/// # Errors
/// Watcher setup failure.
fn start(
    containers: Vec<Tailed>,
    cancel: &CancellationToken,
) -> Result<mpsc::Receiver<DockerLogLine>, notify::Error> {
    let (tx, rx) = mpsc::channel(1024);
    let (raw_tx, raw_rx) = std::sync::mpsc::channel::<Event>();

    let mut watcher = recommended_watcher(move |event| {
        if let Ok(event) = event {
            let _ = raw_tx.send(event);
        }
    })?;

    let mut state: HashMap<PathBuf, Tailed> = containers
        .into_iter()
        .map(|tailed| (tailed.log_path.clone(), tailed))
        .collect();

    for path in state.keys() {
        // Best effort: a watch failure on one file should not kill tailing.
        if let Err(e) = watcher.watch(path, notify::RecursiveMode::NonRecursive) {
            tracing::warn!(path = %path.display(), "watch failed: {e}");
        }
    }

    // Drain-thread: sync notify events -> tokio channel, like the existing
    // `log_scanner` tailer bridge.
    let drain_cancel = cancel.clone();
    std::thread::spawn(move || {
        while !drain_cancel.is_cancelled() {
            match raw_rx.recv_timeout(Duration::from_millis(200)) {
                Ok(event) => {
                    for path in event.paths.iter().map(PathBuf::from).collect::<Vec<_>>() {
                        let Some(tailed) = state.get_mut(&path) else {
                            continue;
                        };
                        let new_lines = read_new_lines(tailed);
                        for line in new_lines {
                            if tx.blocking_send(line).is_err() {
                                return; // receiver dropped
                            }
                        }
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    });

    Ok(rx)
}

/// Reads bytes appended since the saved offset, parsing Docker JSON
/// envelopes; updates the offset. Handles truncation (rotation) by
/// resetting to 0.
fn read_new_lines(tailed: &mut Tailed) -> Vec<DockerLogLine> {
    let Ok(mut file) = std::fs::File::open(&tailed.log_path) else {
        return Vec::new();
    };
    let Ok(size) = file.metadata().map(|meta| meta.len()) else {
        return Vec::new();
    };
    if size < tailed.offset {
        // Truncated (logrotate/docker max-size): start over.
        tracing::info!(container = %tailed.name, "log truncated; resetting offset");
        tailed.offset = 0;
    }
    if size == tailed.offset {
        return Vec::new();
    }
    if file.seek(SeekFrom::Start(tailed.offset)).is_err() {
        return Vec::new();
    }

    let mut buf = String::new();
    if file.read_to_string(&mut buf).is_err() {
        return Vec::new();
    }
    tailed.offset = size;

    buf.lines().filter_map(parse_envelope).collect()
}

/// One Docker JSON envelope line -> log line. Malformed lines are skipped.
fn parse_envelope(raw: &str) -> Option<DockerLogLine> {
    #[derive(Deserialize)]
    struct Envelope {
        #[serde(default)]
        log: String,
        #[serde(default)]
        stream: String,
        time: Option<String>,
    }

    let envelope: Envelope = serde_json::from_str(raw).ok()?;
    if envelope.log.is_empty() {
        return None;
    }
    let message = envelope.log.trim_end_matches('\n').trim_end_matches('\r');
    let timestamp_ms = envelope
        .time
        .and_then(|time| chrono::DateTime::parse_from_rfc3339(&time).ok())
        .map_or_else(crate::agent::metrics::now_millis, |time| {
            time.timestamp_millis()
        });

    Some(DockerLogLine {
        timestamp_ms,
        container: String::new(), // filled by the caller (container is known)
        stream: if envelope.stream.is_empty() {
            "stdout".into()
        } else {
            envelope.stream
        },
        message: message.to_string(),
    })
}

/// The registry result plus tailing start, combined for the run loop.
pub fn tail_containers(
    root: &Path,
    names: &[String],
    cancel: &CancellationToken,
) -> Result<mpsc::Receiver<DockerLogLine>, std::io::Error> {
    let containers = discover(root, names)?;
    start(containers, cancel).map_err(|e| std::io::Error::other(e.to_string()))
}

/// Test shim exposing envelope parsing with a container name attached.
#[allow(dead_code)]
fn parse_envelope_named(raw: &str, container: &str) -> Option<DockerLogLine> {
    parse_envelope(raw).map(|mut line| {
        line.container = container.to_string();
        line
    })
}
