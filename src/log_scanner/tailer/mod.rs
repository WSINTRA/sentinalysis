//! File tailing for the log scanner.
//!
//! `FileTailer` watches explicit files and directories (with glob
//! patterns) using the `notify` crate, reads existing content on start,
//! follows appended data, adopts newly created logs, and handles
//! rotation (`access.log` → `access.log.1`).
//!
//! It emits `TailLine`s (path + line + byte offset) over a tokio channel.
//! The per-file state machine (resume offsets, adopted files, event
//! reactions) lives in [`state::TailerState`].

mod state;

use std::collections::HashSet;
use std::path::PathBuf;

use crossbeam_channel::{Sender as CrossbeamSender, TrySendError, bounded};
use glob::Pattern;
use notify::{Config, Event, EventHandler, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc::{self, Receiver as TokioReceiver};
use tokio_util::sync::CancellationToken;
use tracing::warn;

pub use state::TailerState;

use crate::error::SentinelError;

/// One tailed line: which file it came from, its text, and the byte
/// offset where it started in that file.
#[derive(Debug, Clone)]
pub struct TailLine {
    pub file_path: PathBuf,
    pub line: String,
    pub byte_offset: u64,
}

/// A tailed line or the error that stopped production.
pub type TailEvent = Result<TailLine, SentinelError>;

/// A watched directory plus the file-name glob to tail in it.
#[derive(Debug, Clone)]
pub struct LogWatchConfig {
    pub directory: PathBuf,
    pub pattern: Pattern,
}

impl LogWatchConfig {
    /// Compile the glob; an invalid pattern is a configuration error.
    pub fn new(directory: PathBuf, pattern: &str) -> Result<Self, SentinelError> {
        let pattern = Pattern::new(pattern).map_err(|e| {
            SentinelError::ConfigError(format!("invalid log watch pattern '{pattern}': {e}"))
        })?;
        Ok(Self { directory, pattern })
    }
}

/// Watches log files/directories and emits their new lines.
///
/// Constructing a `FileTailer` is cheap and synchronous; the tokio
/// runtime handle is captured in [`Self::start`], so building one
/// outside a runtime (e.g. in a unit test) is fine.
pub struct FileTailer {
    /// Kept alive for the process lifetime; dropping it stops the watch.
    watcher: Option<RecommendedWatcher>,
    files: Vec<PathBuf>,
    watch_configs: Vec<LogWatchConfig>,
    cancel_token: CancellationToken,
    started: bool,
}

impl Default for FileTailer {
    fn default() -> Self {
        Self {
            watcher: None,
            files: Vec::new(),
            watch_configs: Vec::new(),
            cancel_token: CancellationToken::new(),
            started: false,
        }
    }
}

/// Bridges `notify` (synchronous handler) onto a crossbeam channel.
struct ChannelHandler {
    sender: CrossbeamSender<notify::Result<Event>>,
}

impl EventHandler for ChannelHandler {
    fn handle_event(&mut self, event: notify::Result<Event>) {
        if let Err(e) = self.sender.try_send(event) {
            match e {
                TrySendError::Full(ev) => {
                    warn!("notify channel full, dropping event: {ev:?}");
                }
                TrySendError::Disconnected(_) => {
                    warn!("notify channel disconnected, dropping event");
                }
            }
        }
    }
}

impl FileTailer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Tail these explicit files.
    #[must_use]
    pub fn with_files(mut self, files: Vec<PathBuf>) -> Self {
        self.files = files;
        self
    }

    /// Tail every file matching `pattern` (a glob on the file name) in
    /// `directory`. Fails on an invalid pattern.
    pub fn with_watch_directory(
        mut self,
        directory: PathBuf,
        pattern: &str,
    ) -> Result<Self, SentinelError> {
        self.watch_configs
            .push(LogWatchConfig::new(directory, pattern)?);
        Ok(self)
    }

    /// Start the watcher and background tasks; returns the line stream.
    ///
    /// Initial content of all watched files/directories is read before
    /// the first live event is delivered.
    #[allow(clippy::unused_async, clippy::too_many_lines)]
    pub async fn start(&mut self) -> Result<TokioReceiver<TailEvent>, SentinelError> {
        if self.started {
            return Err(SentinelError::Internal("Tailer already started".into()));
        }

        let (tx, rx) = mpsc::channel::<TailEvent>(1024);
        let (notify_tx, notify_rx) = bounded::<notify::Result<Event>>(128);

        let config = Config::default()
            .with_poll_interval(std::time::Duration::from_millis(100))
            .with_compare_contents(true);

        let handler = ChannelHandler { sender: notify_tx };
        let mut watcher = RecommendedWatcher::new(handler, config)?;

        let files = self.files.clone();
        let watch_configs = self.watch_configs.clone();
        let cancel = self.cancel_token.clone();

        for file in &files {
            if file.exists() {
                watcher.watch(file, RecursiveMode::NonRecursive)?;
            }
        }

        for cfg in &watch_configs {
            if cfg.directory.is_dir() {
                watcher.watch(&cfg.directory, RecursiveMode::NonRecursive)?;
            }
        }

        self.watcher = Some(watcher);
        self.started = true;

        // Bridge: notify handler thread (sync) → tokio task (async).
        let (event_tx, mut event_rx) = mpsc::channel::<notify::Result<Event>>(128);
        let rt = tokio::runtime::Handle::current();
        tokio::spawn(async move {
            let _ = tokio::task::spawn_blocking(move || {
                while let Ok(event) = notify_rx.recv() {
                    if rt.block_on(event_tx.send(event)).is_err() {
                        break;
                    }
                }
            })
            .await;
        });

        let watched_dirs: HashSet<PathBuf> = watch_configs
            .iter()
            .map(|cfg| cfg.directory.clone())
            .collect();

        // The tailing loop: initial read, then live events forever.
        tokio::spawn(async move {
            let mut state = TailerState::new(files.clone());

            for file in &files {
                if let Err(e) = state.read_existing_lines(file, &tx).await {
                    let _ = tx.send(Err(e)).await;
                }
            }

            for cfg in &watch_configs {
                if let Err(e) = state.discover_existing_logs(cfg, &tx).await {
                    let _ = tx.send(Err(e)).await;
                }
            }

            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,

                    maybe_event = event_rx.recv() => {
                        let Some(Ok(event)) = maybe_event else {
                            break;
                        };

                        if let Err(e) = state
                            .handle_event(event, &watch_configs, &watched_dirs, &tx)
                            .await
                        {
                            let _ = tx.send(Err(e)).await;
                        }
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Stop the tailer; in-flight tasks exit on the next cancellation
    /// check.
    pub fn stop(&self) {
        self.cancel_token.cancel();
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.started && !self.cancel_token.is_cancelled()
    }

    #[must_use]
    pub fn watched_files(&self) -> &[PathBuf] {
        &self.files
    }
}

impl Drop for FileTailer {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::Duration;
    use tempfile::{NamedTempFile, TempDir};

    fn create_test_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{content}").unwrap();
        file.flush().unwrap();
        file
    }

    /// Receive up to `count` lines from the stream, bounded by `timeout`.
    async fn collect_lines(
        rx: &mut TokioReceiver<TailEvent>,
        count: usize,
        timeout: Duration,
    ) -> Vec<TailLine> {
        let mut lines = Vec::new();
        let _ = tokio::time::timeout(timeout, async {
            while let Some(event) = rx.recv().await {
                if let Ok(line) = event {
                    lines.push(line);
                    if lines.len() >= count {
                        break;
                    }
                }
            }
        })
        .await;
        lines
    }

    #[tokio::test]
    async fn test_tailer_is_created() {
        let tailer = FileTailer::new();
        assert!(tailer.watched_files().is_empty());
        assert!(!tailer.is_running());
    }

    #[tokio::test]
    async fn test_tailer_with_files() {
        let temp_dir = TempDir::new().unwrap();
        let file1 = temp_dir.path().join("test1.log");
        let file2 = temp_dir.path().join("test2.log");

        let tailer = FileTailer::new().with_files(vec![file1.clone(), file2.clone()]);
        assert_eq!(tailer.watched_files().len(), 2);
    }

    #[tokio::test]
    async fn test_tailer_with_watch_directory_invalid_pattern_fails() {
        let result = FileTailer::new().with_watch_directory(PathBuf::from("/tmp"), "[invalid");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tailer_starts() {
        let temp_dir = TempDir::new().unwrap();
        let file = temp_dir.path().join("test.log");
        std::fs::write(&file, "initial line\n").unwrap();

        let mut tailer = FileTailer::new().with_files(vec![file]);
        let rx = tailer.start().await.unwrap();
        assert!(tailer.is_running());
        drop(rx);
        tailer.stop();
    }

    #[tokio::test]
    async fn test_tailer_reads_existing_content() {
        let file = create_test_file("line1\nline2\nline3");
        let path = file.path().to_path_buf();

        let mut tailer = FileTailer::new().with_files(vec![path]);
        let mut rx = tailer.start().await.unwrap();

        let lines = collect_lines(&mut rx, 3, Duration::from_secs(2)).await;

        tailer.stop();
        let got: Vec<&str> = lines.iter().map(|l| l.line.as_str()).collect();
        assert!(got.contains(&"line1"));
        assert!(got.contains(&"line2"));
        assert!(got.contains(&"line3"));
    }

    #[tokio::test]
    #[cfg_attr(target_os = "macos", ignore = "Flaky on macOS FSEvents")]
    async fn test_tailer_detects_new_lines() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.log");

        std::fs::write(&path, "initial\n").unwrap();

        let mut tailer = FileTailer::new().with_files(vec![path.clone()]);
        let mut rx = tailer.start().await.unwrap();

        // Wait for initial read
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Append new line with sync
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(f, "new line").unwrap();
        f.sync_all().unwrap();
        drop(f);

        // Give notify time to deliver the event
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut new_lines = Vec::new();
        tokio::select! {
            () = async {
                while let Some(event) = rx.recv().await {
                    if let Ok(line) = event
                        && line.line == "new line" {
                            new_lines.push(line.line);
                        }
                }
            } => {},
            () = tokio::time::sleep(Duration::from_secs(5)) => {},
        }

        tailer.stop();
        assert!(
            !new_lines.is_empty(),
            "Expected to detect new line via file watching"
        );
    }

    #[tokio::test]
    async fn test_tailer_tracks_byte_offset() {
        let file = create_test_file("first line");
        let path = file.path().to_path_buf();

        let mut tailer = FileTailer::new().with_files(vec![path]);
        let mut rx = tailer.start().await.unwrap();

        let lines = collect_lines(&mut rx, 1, Duration::from_secs(2)).await;

        tailer.stop();
        assert!(!lines.is_empty());
        assert_eq!(lines[0].byte_offset, 0);
    }

    #[tokio::test]
    async fn test_tailer_tracks_file_path() {
        let file = create_test_file("test");
        let path = file.path().to_path_buf();

        let mut tailer = FileTailer::new().with_files(vec![path.clone()]);
        let mut rx = tailer.start().await.unwrap();

        let lines = collect_lines(&mut rx, 1, Duration::from_secs(2)).await;

        tailer.stop();
        assert!(!lines.is_empty());
        assert_eq!(lines[0].file_path, path);
    }

    #[tokio::test]
    async fn test_tailer_stop() {
        let temp_dir = TempDir::new().unwrap();
        let file = temp_dir.path().join("test.log");
        std::fs::write(&file, "test\n").unwrap();

        let mut tailer = FileTailer::new().with_files(vec![file]);
        let _rx = tailer.start().await.unwrap();
        assert!(tailer.is_running());

        tailer.stop();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!tailer.is_running());
    }

    #[tokio::test]
    async fn test_tailer_multiple_files() {
        let temp_dir = TempDir::new().unwrap();
        let file1 = temp_dir.path().join("test1.log");
        let file2 = temp_dir.path().join("test2.log");

        std::fs::write(&file1, "from file1\n").unwrap();
        std::fs::write(&file2, "from file2\n").unwrap();

        let mut tailer = FileTailer::new().with_files(vec![file1.clone(), file2.clone()]);
        let mut rx = tailer.start().await.unwrap();

        let lines = collect_lines(&mut rx, 2, Duration::from_secs(2)).await;

        tailer.stop();
        let got: Vec<&str> = lines.iter().map(|l| l.line.as_str()).collect();
        assert!(got.contains(&"from file1"));
        assert!(got.contains(&"from file2"));
    }

    #[tokio::test]
    async fn test_tailer_duplicate_start_fails() {
        let temp_dir = TempDir::new().unwrap();
        let file = temp_dir.path().join("test.log");
        std::fs::write(&file, "test\n").unwrap();

        let mut tailer = FileTailer::new().with_files(vec![file]);
        let _rx1 = tailer.start().await.unwrap();
        let result = tailer.start().await;
        tailer.stop();

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tailer_discovers_existing_logs_in_directory() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path().join("logs");
        std::fs::create_dir(&log_dir).unwrap();

        std::fs::write(log_dir.join("app.log"), "from app\n").unwrap();
        std::fs::write(log_dir.join("web.log"), "from web\n").unwrap();
        std::fs::write(log_dir.join("app.log.1"), "rotated\n").unwrap();

        let mut tailer = FileTailer::new()
            .with_watch_directory(log_dir, "*.log")
            .unwrap();
        let mut rx = tailer.start().await.unwrap();

        let lines = collect_lines(&mut rx, 2, Duration::from_secs(2)).await;

        tailer.stop();
        let got: Vec<&str> = lines.iter().map(|l| l.line.as_str()).collect();
        assert!(got.contains(&"from app"));
        assert!(got.contains(&"from web"));
        assert!(!got.contains(&"rotated"));
    }

    #[tokio::test]
    #[cfg_attr(target_os = "macos", ignore = "Flaky on macOS FSEvents")]
    async fn test_tailer_auto_tails_new_log_in_directory() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path().join("logs");
        std::fs::create_dir(&log_dir).unwrap();

        let mut tailer = FileTailer::new()
            .with_watch_directory(log_dir.clone(), "*.log")
            .unwrap();
        let mut rx = tailer.start().await.unwrap();

        tokio::time::sleep(Duration::from_millis(300)).await;

        let new_log = log_dir.join("new-service.log");
        std::fs::write(&new_log, "new service line\n").unwrap();

        let mut lines = Vec::new();
        tokio::select! {
            () = async {
                while let Some(event) = rx.recv().await {
                    if let Ok(line) = event {
                        lines.push((line.file_path.clone(), line.line));
                    }
                }
            } => {},
            () = tokio::time::sleep(Duration::from_secs(3)) => {},
        }

        tailer.stop();

        let found = lines.iter().any(|(path, line)| {
            path.file_name().is_some_and(|n| n == "new-service.log") && line == "new service line"
        });
        assert!(found, "Expected to auto-tail new log file, got: {lines:?}");
    }

    #[tokio::test]
    #[cfg_attr(target_os = "macos", ignore = "Flaky on macOS FSEvents")]
    async fn test_tailer_handles_log_rotation() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path().join("logs");
        std::fs::create_dir(&log_dir).unwrap();

        let log_path = log_dir.join("app.log");
        std::fs::write(&log_path, "before rotation\n").unwrap();

        let mut tailer = FileTailer::new()
            .with_watch_directory(log_dir.clone(), "*.log")
            .unwrap();
        let mut rx = tailer.start().await.unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;

        let rotated_path = log_dir.join("app.log.1");
        std::fs::rename(&log_path, &rotated_path).unwrap();

        tokio::time::sleep(Duration::from_millis(200)).await;

        std::fs::write(&log_path, "after rotation\n").unwrap();

        let mut lines = Vec::new();
        tokio::select! {
            () = async {
                while let Some(event) = rx.recv().await {
                    if let Ok(line) = event {
                        lines.push(line.line);
                    }
                }
            } => {},
            () = tokio::time::sleep(Duration::from_secs(3)) => {},
        }

        tailer.stop();

        assert!(
            lines.iter().any(|l| l == "after rotation"),
            "Expected to tail new file after rotation, got: {lines:?}"
        );
    }

    #[tokio::test]
    #[cfg_attr(target_os = "macos", ignore = "Flaky on macOS FSEvents")]
    async fn test_tailer_ignores_rotated_files_created_directly() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path().join("logs");
        std::fs::create_dir(&log_dir).unwrap();

        let mut tailer = FileTailer::new()
            .with_watch_directory(log_dir.clone(), "*.log")
            .unwrap();
        let mut rx = tailer.start().await.unwrap();

        tokio::time::sleep(Duration::from_millis(300)).await;

        std::fs::write(log_dir.join("app.log.1"), "should not be tailed\n").unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut lines = Vec::new();
        tokio::select! {
            () = async {
                while let Some(event) = rx.recv().await {
                    if let Ok(line) = event {
                        lines.push(line.line);
                    }
                }
            } => {},
            () = tokio::time::sleep(Duration::from_secs(2)) => {},
        }

        tailer.stop();
        assert!(
            lines.is_empty() || !lines.iter().any(|l| l == "should not be tailed"),
            "Rotated file should not be tailed, got: {lines:?}"
        );
    }

    #[tokio::test]
    async fn test_tailer_combines_files_and_directory() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path().join("logs");
        std::fs::create_dir(&log_dir).unwrap();

        let specific_file = temp_dir.path().join("auth.log");
        std::fs::write(&specific_file, "auth line\n").unwrap();
        std::fs::write(log_dir.join("app.log"), "app line\n").unwrap();

        let mut tailer = FileTailer::new().with_files(vec![specific_file]);
        tailer = tailer.with_watch_directory(log_dir, "*.log").unwrap();
        let mut rx = tailer.start().await.unwrap();

        let lines = collect_lines(&mut rx, 2, Duration::from_secs(2)).await;

        tailer.stop();
        let got: Vec<&str> = lines.iter().map(|l| l.line.as_str()).collect();
        assert!(got.contains(&"auth line"));
        assert!(got.contains(&"app line"));
    }
}
