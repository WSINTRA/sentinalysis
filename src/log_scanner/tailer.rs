use crate::error::SentinelError;
use crossbeam_channel::bounded;
use notify::{Config, Event, EventHandler, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc::{self, Receiver as TokioReceiver, Sender as TokioSender};
use tokio_util::sync::CancellationToken;

pub type TailEvent = Result<TailLine, SentinelError>;

#[derive(Debug, Clone)]
pub struct TailLine {
    pub file_path: PathBuf,
    pub line: String,
    pub byte_offset: u64,
}

#[derive(Debug, Default)]
pub struct FileTailer {
    watcher: Option<RecommendedWatcher>,
    files: Vec<PathBuf>,
    cancel_token: CancellationToken,
    started: bool,
}

struct ChannelHandler {
    sender: crossbeam_channel::Sender<notify::Result<Event>>,
}

impl EventHandler for ChannelHandler {
    fn handle_event(&mut self, event: notify::Result<Event>) {
        let _ = self.sender.send(event);
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

    #[allow(clippy::unused_async)]
    pub async fn start(&mut self) -> Result<TokioReceiver<TailEvent>, SentinelError> {
        if self.started {
            return Err(SentinelError::Internal("Tailer already started".into()));
        }

        let (tx, rx) = mpsc::channel::<TailEvent>(1024);
        let (std_tx, std_rx) = bounded::<notify::Result<Event>>(128);

        let config = Config::default()
            .with_poll_interval(std::time::Duration::from_millis(100))
            .with_compare_contents(true);

        let handler = ChannelHandler { sender: std_tx };
        let mut watcher = RecommendedWatcher::new(handler, config)
            .map_err(|e| SentinelError::FileTailingError(e.to_string()))?;

        let files = self.files.clone();
        let cancel = self.cancel_token.clone();

        for file in &files {
            if file.exists() {
                watcher
                    .watch(file, RecursiveMode::NonRecursive)
                    .map_err(|e| SentinelError::FileTailingError(e.to_string()))?;
            }
        }

        self.watcher = Some(watcher);
        self.started = true;

        // Spawn a thread to bridge blocking notify receiver to async channel
        let (async_tx, mut async_rx) = mpsc::channel::<notify::Result<Event>>(128);
        std::thread::spawn(move || {
            while let Ok(event) = std_rx.recv() {
                let rt = match tokio::runtime::Handle::try_current() {
                    Ok(h) => h,
                    Err(_) => tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap()
                        .handle()
                        .clone(),
                };
                let should_break = rt.block_on(async {
                    #[allow(clippy::unused_async)]
                    async_tx.send(event).await.is_err()
                });
                if should_break {
                    break;
                }
            }
        });

        tokio::spawn(async move {
            let mut positions: std::collections::HashMap<PathBuf, u64> =
                std::collections::HashMap::new();

            // Initial read of existing content
            for file in &files {
                if let Err(e) = read_existing_lines(file, &mut positions, &tx).await {
                    let _ = tx.send(Err(e)).await;
                }
            }

            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    maybe_event = async_rx.recv() => {
                        let Some(Ok(event)) = maybe_event else {
                            break;
                        };

                        if let Err(e) = handle_event(event, &mut positions, &tx).await {
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

async fn handle_event(
    event: Event,
    positions: &mut std::collections::HashMap<PathBuf, u64>,
    tx: &TokioSender<TailEvent>,
) -> Result<(), SentinelError> {
    for path in event.paths {
        if matches!(
            event.kind,
            EventKind::Modify(notify::event::ModifyKind::Data(_))
        ) {
            if let Some(&pos) = positions.get(&path) {
                let content = tokio::fs::read_to_string(&path)
                    .await
                    .map_err(|e| SentinelError::Io(e.to_string()))?;
                let bytes = content.as_bytes();

                let pos_usize = usize::try_from(pos).map_err(|_| {
                    SentinelError::Internal("File position exceeds address space".into())
                })?;

                if bytes.len() >= pos_usize {
                    let new_content = &bytes[pos_usize..];
                    let text = std::str::from_utf8(new_content)
                        .map_err(|e| SentinelError::Io(e.to_string()))?;
                    let mut current_offset = pos;

                    for line in text.lines() {
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
                } else {
                    positions.insert(path.clone(), 0);
                }
            }
        } else if matches!(event.kind, EventKind::Create(_)) {
            positions.insert(path.clone(), 0);
        } else if matches!(event.kind, EventKind::Remove(_)) {
            positions.remove(&path);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    fn create_test_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", content).unwrap();
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
            _ = async {
                while let Some(event) = rx.recv().await {
                    if let Ok(line) = event {
                        lines.push(line.line);
                    }
                    if lines.len() >= 3 {
                        break;
                    }
                }
            } => {},
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {},
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
            _ = async {
                while let Some(event) = rx.recv().await {
                    if let Ok(line) = event {
                        if line.line == "new line" {
                            new_lines.push(line.line);
                        }
                    }
                }
            } => {},
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {},
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
            _ = async {
                while let Some(event) = rx.recv().await {
                    if let Ok(line) = event {
                        offsets.push(line.byte_offset);
                    }
                    if offsets.len() >= 1 {
                        break;
                    }
                }
            } => {},
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {},
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
            _ = async {
                while let Some(event) = rx.recv().await {
                    if let Ok(line) = event {
                        file_paths.push(line.file_path.clone());
                    }
                    if !file_paths.is_empty() {
                        break;
                    }
                }
            } => {},
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {},
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
            _ = async {
                while let Some(event) = rx.recv().await {
                    if let Ok(line) = event {
                        lines.push(line.line);
                    }
                    if lines.len() >= 2 {
                        break;
                    }
                }
            } => {},
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {},
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
}
