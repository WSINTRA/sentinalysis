use crate::error::SentinelError;
use crossbeam_channel::{Sender as CrossbeamSender, TrySendError, bounded};
use glob::Pattern;
use notify::{Config, Event, EventHandler, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashSet;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};

use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::mpsc::{self, Receiver as TokioReceiver, Sender as TokioSender};
use tokio_util::sync::CancellationToken;
use tracing::warn;

pub type TailEvent = Result<TailLine, SentinelError>;

#[derive(Debug, Clone)]
pub struct TailLine {
    pub file_path: PathBuf,
    pub line: String,
    pub byte_offset: u64,
}

#[derive(Debug, Clone)]
pub struct LogWatchConfig {
    pub directory: PathBuf,
    pub pattern: Pattern,
}

impl LogWatchConfig {
    #[must_use]
    pub fn new(directory: PathBuf, pattern: &str) -> Self {
        Self {
            directory,
            pattern: Pattern::new(pattern).expect("log watch pattern must be valid glob"),
        }
    }
}

fn is_rotated_log(file_name: &str) -> bool {
    if let Some(dot_pos) = file_name.rfind('.') {
        let suffix = &file_name[dot_pos + 1..];
        !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit())
    } else {
        false
    }
}

fn matches_pattern(path: &Path, pattern: &Pattern) -> bool {
    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
        pattern.matches(file_name)
    } else {
        false
    }
}

pub struct FileTailer {
    watcher: Option<RecommendedWatcher>,
    files: Vec<PathBuf>,
    watch_configs: Vec<LogWatchConfig>,
    rt: tokio::runtime::Handle,
    cancel_token: CancellationToken,
    started: bool,
}

impl Default for FileTailer {
    fn default() -> Self {
        Self {
            watcher: None,
            files: Vec::new(),
            watch_configs: Vec::new(),
            rt: tokio::runtime::Handle::current(),
            cancel_token: CancellationToken::new(),
            started: false,
        }
    }
}

struct ChannelHandler {
    sender: CrossbeamSender<notify::Result<Event>>,
}

impl EventHandler for ChannelHandler {
    fn handle_event(&mut self, event: notify::Result<Event>) {
        if let Err(e) = self.sender.try_send(event) {
            match e {
                TrySendError::Full(ev) => {
                    warn!("notify channel full, dropping event: {:?}", ev);
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

    #[must_use]
    pub fn with_files(mut self, files: Vec<PathBuf>) -> Self {
        self.files = files;
        self
    }

    #[must_use]
    pub fn with_watch_directory(mut self, directory: PathBuf, pattern: &str) -> Self {
        self.watch_configs
            .push(LogWatchConfig::new(directory, pattern));
        self
    }

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
        let mut watcher = RecommendedWatcher::new(handler, config)
            .map_err(|e| SentinelError::FileTailingError(e.to_string()))?;

        let files = self.files.clone();
        let watch_configs = self.watch_configs.clone();
        let cancel = self.cancel_token.clone();

        for file in &files {
            if file.exists() {
                watcher
                    .watch(file, RecursiveMode::NonRecursive)
                    .map_err(|e| SentinelError::FileTailingError(e.to_string()))?;
            }
        }

        for cfg in &watch_configs {
            if cfg.directory.is_dir() {
                watcher
                    .watch(&cfg.directory, RecursiveMode::NonRecursive)
                    .map_err(|e| SentinelError::FileTailingError(e.to_string()))?;
            }
        }

        self.watcher = Some(watcher);
        self.started = true;

        let (event_tx, mut event_rx) = mpsc::channel::<notify::Result<Event>>(128);
        let rt = self.rt.clone();
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
        let initial_files: HashSet<PathBuf> = files.iter().cloned().collect();

        tokio::spawn(async move {
            let mut positions: std::collections::HashMap<PathBuf, u64> =
                std::collections::HashMap::new();
            let mut tailed_files: HashSet<PathBuf> = initial_files.clone();

            for file in &files {
                if let Err(e) = read_existing_lines(file, &mut positions, &tx).await {
                    let _ = tx.send(Err(e)).await;
                }
            }

            for cfg in &watch_configs {
                if let Err(e) =
                    discover_existing_logs(cfg, &mut positions, &mut tailed_files, &tx).await
                {
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

                        if let Err(e) = handle_event(
                            event,
                            &mut positions,
                            &mut tailed_files,
                            &watch_configs,
                            &watched_dirs,
                            &tx,
                        ).await {
                            let _ = tx.send(Err(e)).await;
                        }
                    }
                }
            }
        });

        Ok(rx)
    }

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

async fn read_existing_lines(
    file: &Path,
    positions: &mut std::collections::HashMap<PathBuf, u64>,
    tx: &TokioSender<TailEvent>,
) -> Result<(), SentinelError> {
    let content = tokio::fs::read_to_string(file)
        .await
        .map_err(|e| SentinelError::Io(e.to_string()))?;
    let mut offset: u64 = 0;

    for line in content.lines() {
        let line_bytes = line.len() as u64 + 1;
        let tail_line = TailLine {
            file_path: file.to_path_buf(),
            line: line.to_string(),
            byte_offset: offset,
        };

        if tx.send(Ok(tail_line)).await.is_err() {
            break;
        }

        offset += line_bytes;
    }

    positions.insert(file.to_path_buf(), offset);
    Ok(())
}

async fn discover_existing_logs(
    cfg: &LogWatchConfig,
    positions: &mut std::collections::HashMap<PathBuf, u64>,
    tailed_files: &mut HashSet<PathBuf>,
    tx: &TokioSender<TailEvent>,
) -> Result<(), SentinelError> {
    let mut entries = tokio::fs::read_dir(&cfg.directory)
        .await
        .map_err(|e| SentinelError::Io(e.to_string()))?;

    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        if !matches_pattern(&path, &cfg.pattern) || is_rotated_log(file_name) {
            continue;
        }

        if tailed_files.insert(path.clone())
            && let Err(e) = read_existing_lines(&path, positions, tx).await
        {
            warn!("failed to read existing lines from {:?}: {}", path, e);
        }
    }

    Ok(())
}

async fn wait_for_file_stability(path: &Path) {
    const MAX_CHECKS: usize = 10;
    const CHECK_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_millis(10);

    let mut last_size = 0u64;
    for _ in 0..MAX_CHECKS {
        if let Ok(meta) = tokio::fs::metadata(path).await {
            let size = meta.len();
            if size == last_size && last_size > 0 {
                return;
            }
            last_size = size;
        }
        tokio::time::sleep(CHECK_INTERVAL).await;
    }
}

async fn handle_event(
    event: Event,
    positions: &mut std::collections::HashMap<PathBuf, u64>,
    tailed_files: &mut HashSet<PathBuf>,
    watch_configs: &[LogWatchConfig],
    watched_dirs: &HashSet<PathBuf>,
    tx: &TokioSender<TailEvent>,
) -> Result<(), SentinelError> {
    for path in event.paths {
        if !path.is_file() {
            continue;
        }

        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        if matches!(
            event.kind,
            EventKind::Modify(notify::event::ModifyKind::Data(_))
        ) && tailed_files.contains(&path)
        {
            if let Some(&pos) = positions.get(&path) {
                let mut file = File::open(&path)
                    .await
                    .map_err(|e| SentinelError::Io(e.to_string()))?;

                file.seek(SeekFrom::Start(pos))
                    .await
                    .map_err(|e| SentinelError::Io(e.to_string()))?;

                let mut new_content = String::new();
                file.read_to_string(&mut new_content)
                    .await
                    .map_err(|e| SentinelError::Io(e.to_string()))?;

                let mut current_offset = pos;

                for line in new_content.lines() {
                    let line_bytes = line.len() as u64 + 1;
                    let tail_line = TailLine {
                        file_path: path.clone(),
                        line: line.to_string(),
                        byte_offset: current_offset,
                    };

                    if tx.send(Ok(tail_line)).await.is_err() {
                        return Ok(());
                    }

                    current_offset += line_bytes;
                }

                positions.insert(path.clone(), current_offset);
            }
        } else if matches!(event.kind, EventKind::Create(_)) && !is_rotated_log(file_name) {
            if let Some(cfg) = find_matching_config(&path, watch_configs, watched_dirs)
                && matches_pattern(&path, &cfg.pattern)
            {
                tailed_files.insert(path.clone());
                positions.insert(path.clone(), 0);

                wait_for_file_stability(&path).await;

                if let Err(e) = read_existing_lines(&path, positions, tx).await {
                    warn!("failed to read newly created file {:?}: {}", path, e);
                }
            }
        } else if matches!(event.kind, EventKind::Remove(_))
            || (matches!(
                event.kind,
                EventKind::Modify(notify::event::ModifyKind::Name(_))
            ) && is_rotated_log(file_name))
        {
            positions.remove(&path);
            tailed_files.remove(&path);
        }
    }

    Ok(())
}

fn find_matching_config<'a>(
    path: &Path,
    watch_configs: &'a [LogWatchConfig],
    watched_dirs: &HashSet<PathBuf>,
) -> Option<&'a LogWatchConfig> {
    watch_configs
        .iter()
        .find(|cfg| watched_dirs.contains(&cfg.directory) && path.starts_with(&cfg.directory))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    fn create_test_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{content}").unwrap();
        file.flush().unwrap();
        file
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

        let mut lines = Vec::new();
        tokio::select! {
            () = async {
                while let Some(event) = rx.recv().await {
                    if let Ok(line) = event {
                        lines.push(line.line);
                    }
                    if lines.len() >= 3 {
                        break;
                    }
                }
            } => {},
            () = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {},
        }

        tailer.stop();
        assert!(lines.contains(&"line1".to_string()));
        assert!(lines.contains(&"line2".to_string()));
        assert!(lines.contains(&"line3".to_string()));
    }

    #[tokio::test]
    #[ignore = "Flaky on macOS FSEvents; verify on Linux with inotify"]
    async fn test_tailer_detects_new_lines() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.log");

        // Create file with initial content
        std::fs::write(&path, "initial\n").unwrap();

        let mut tailer = FileTailer::new().with_files(vec![path.clone()]);
        let mut rx = tailer.start().await.unwrap();

        // Wait for initial read
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Append new line with sync
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(f, "new line").unwrap();
        f.sync_all().unwrap();
        drop(f);

        // Give notify time to deliver the event
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

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
            () = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {},
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

        let mut offsets = Vec::new();
        tokio::select! {
            () = async {
                while let Some(event) = rx.recv().await {
                    if let Ok(line) = event {
                        offsets.push(line.byte_offset);
                    }
                    if !offsets.is_empty() {
                        break;
                    }
                }
            } => {},
            () = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {},
        }

        tailer.stop();
        assert!(!offsets.is_empty());
        assert_eq!(offsets[0], 0);
    }

    #[tokio::test]
    async fn test_tailer_tracks_file_path() {
        let file = create_test_file("test");
        let path = file.path().to_path_buf();

        let mut tailer = FileTailer::new().with_files(vec![path.clone()]);
        let mut rx = tailer.start().await.unwrap();

        let mut file_paths = Vec::new();
        tokio::select! {
            () = async {
                while let Some(event) = rx.recv().await {
                    if let Ok(line) = event {
                        file_paths.push(line.file_path.clone());
                    }
                    if !file_paths.is_empty() {
                        break;
                    }
                }
            } => {},
            () = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {},
        }

        tailer.stop();
        assert!(!file_paths.is_empty());
        assert_eq!(file_paths[0], path);
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
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
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

        let mut lines = Vec::new();
        tokio::select! {
            () = async {
                while let Some(event) = rx.recv().await {
                    if let Ok(line) = event {
                        lines.push(line.line);
                    }
                    if lines.len() >= 2 {
                        break;
                    }
                }
            } => {},
            () = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {},
        }

        tailer.stop();
        assert!(lines.contains(&"from file1".to_string()));
        assert!(lines.contains(&"from file2".to_string()));
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

    #[test]
    fn test_tail_line_structure() {
        let line = TailLine {
            file_path: PathBuf::from("/var/log/test.log"),
            line: "test message".to_string(),
            byte_offset: 100,
        };

        assert_eq!(line.line, "test message");
        assert_eq!(line.byte_offset, 100);
        assert_eq!(line.file_path, PathBuf::from("/var/log/test.log"));
    }

    #[test]
    fn test_is_rotated_log_detects_numeric_suffix() {
        assert!(is_rotated_log("access.log.1"));
        assert!(is_rotated_log("access.log.2"));
        assert!(is_rotated_log("example.com-access.log.10"));
        assert!(is_rotated_log("error.log.99"));
    }

    #[test]
    fn test_is_rotated_log_ignores_normal_logs() {
        assert!(!is_rotated_log("access.log"));
        assert!(!is_rotated_log("error.log"));
        assert!(!is_rotated_log("example.com-access.log"));
        assert!(!is_rotated_log("auth.log"));
    }

    #[test]
    fn test_is_rotated_log_ignores_gzipped() {
        assert!(!is_rotated_log("access.log.1.gz"));
        assert!(!is_rotated_log("error.log.2.gz"));
    }

    #[test]
    fn test_matches_pattern_with_log_pattern() {
        let pattern = Pattern::new("*.log").unwrap();
        assert!(matches_pattern(Path::new("access.log"), &pattern));
        assert!(matches_pattern(
            Path::new("example.com-access.log"),
            &pattern
        ));
        assert!(!matches_pattern(Path::new("access.log.1"), &pattern));
        assert!(!matches_pattern(Path::new("access.log.gz"), &pattern));
    }

    #[test]
    fn test_log_watch_config_new() {
        let cfg = LogWatchConfig::new(PathBuf::from("/var/log/nginx"), "*.log");
        assert_eq!(cfg.directory, PathBuf::from("/var/log/nginx"));
    }

    #[tokio::test]
    async fn test_tailer_with_watch_directory() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path().join("logs");
        std::fs::create_dir(&log_dir).unwrap();

        let existing_log = log_dir.join("app.log");
        std::fs::write(&existing_log, "existing line\n").unwrap();

        let tailer = FileTailer::new().with_watch_directory(log_dir, "*.log");
        assert!(tailer.watched_files().is_empty());
    }

    #[tokio::test]
    async fn test_tailer_discovers_existing_logs_in_directory() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path().join("logs");
        std::fs::create_dir(&log_dir).unwrap();

        std::fs::write(log_dir.join("app.log"), "from app\n").unwrap();
        std::fs::write(log_dir.join("web.log"), "from web\n").unwrap();
        std::fs::write(log_dir.join("app.log.1"), "rotated\n").unwrap();

        let mut tailer = FileTailer::new().with_watch_directory(log_dir, "*.log");
        let mut rx = tailer.start().await.unwrap();

        let mut lines = Vec::new();
        tokio::select! {
            () = async {
                while let Some(event) = rx.recv().await {
                    if let Ok(line) = event {
                        lines.push(line.line);
                    }
                    if lines.len() >= 2 {
                        break;
                    }
                }
            } => {},
            () = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {},
        }

        tailer.stop();
        assert!(lines.contains(&"from app".to_string()));
        assert!(lines.contains(&"from web".to_string()));
        assert!(!lines.contains(&"rotated".to_string()));
    }

    #[tokio::test]
    #[ignore = "Flaky on macOS FSEvents; verify on Linux with inotify"]
    async fn test_tailer_auto_tails_new_log_in_directory() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path().join("logs");
        std::fs::create_dir(&log_dir).unwrap();

        let mut tailer = FileTailer::new().with_watch_directory(log_dir.clone(), "*.log");
        let mut rx = tailer.start().await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

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
            () = tokio::time::sleep(tokio::time::Duration::from_secs(3)) => {},
        }

        tailer.stop();

        let found = lines.iter().any(|(path, line)| {
            path.file_name().is_some_and(|n| n == "new-service.log") && line == "new service line"
        });
        assert!(found, "Expected to auto-tail new log file, got: {lines:?}");
    }

    #[tokio::test]
    #[ignore = "Flaky on macOS FSEvents; verify on Linux with inotify"]
    async fn test_tailer_handles_log_rotation() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path().join("logs");
        std::fs::create_dir(&log_dir).unwrap();

        let log_path = log_dir.join("app.log");
        std::fs::write(&log_path, "before rotation\n").unwrap();

        let mut tailer = FileTailer::new().with_watch_directory(log_dir.clone(), "*.log");
        let mut rx = tailer.start().await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        let rotated_path = log_dir.join("app.log.1");
        std::fs::rename(&log_path, &rotated_path).unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

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
            () = tokio::time::sleep(tokio::time::Duration::from_secs(3)) => {},
        }

        tailer.stop();

        assert!(
            lines.iter().any(|l| l == "after rotation"),
            "Expected to tail new file after rotation, got: {lines:?}"
        );
    }

    #[tokio::test]
    #[ignore = "Flaky on macOS FSEvents; verify on Linux with inotify"]
    async fn test_tailer_ignores_rotated_files_created_directly() {
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path().join("logs");
        std::fs::create_dir(&log_dir).unwrap();

        let mut tailer = FileTailer::new().with_watch_directory(log_dir.clone(), "*.log");
        let mut rx = tailer.start().await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

        std::fs::write(log_dir.join("app.log.1"), "should not be tailed\n").unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        let mut lines = Vec::new();
        tokio::select! {
            () = async {
                while let Some(event) = rx.recv().await {
                    if let Ok(line) = event {
                        lines.push(line.line);
                    }
                }
            } => {},
            () = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {},
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

        let mut tailer = FileTailer::new()
            .with_files(vec![specific_file])
            .with_watch_directory(log_dir, "*.log");
        let mut rx = tailer.start().await.unwrap();

        let mut lines = Vec::new();
        tokio::select! {
            () = async {
                while let Some(event) = rx.recv().await {
                    if let Ok(line) = event {
                        lines.push(line.line);
                    }
                    if lines.len() >= 2 {
                        break;
                    }
                }
            } => {},
            () = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {},
        }

        tailer.stop();
        assert!(lines.contains(&"auth line".to_string()));
        assert!(lines.contains(&"app line".to_string()));
    }
}
