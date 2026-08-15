//! Tailer state machine.
//!
//! `TailerState` owns everything that must survive between file events:
//! the per-file byte position to resume reading from, and the set of
//! files currently being tailed. All the logic that reacts to a
//! `notify` event lives here so it can be unit-tested without spawning
//! watcher tasks.

use std::collections::{HashMap, HashSet};
use std::io::SeekFrom;
use std::path::{Path, PathBuf};

use glob::Pattern;
use notify::{Event, EventKind};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::mpsc::Sender as TokioSender;
use tracing::warn;

use super::{LogWatchConfig, TailEvent, TailLine};
use crate::error::SentinelError;
use crate::log_scanner::source::is_rotated_log;

/// Resumable reading state for the files and directories being tailed.
pub struct TailerState {
    /// Byte offset to resume reading from, per file.
    positions: HashMap<PathBuf, u64>,
    /// Files whose content is already being tracked.
    tailed_files: HashSet<PathBuf>,
}

impl TailerState {
    #[must_use]
    pub fn new(initial_files: Vec<PathBuf>) -> Self {
        Self {
            positions: HashMap::new(),
            tailed_files: initial_files.into_iter().collect(),
        }
    }

    /// Read everything already in `file`, emit the lines, and record the
    /// end position as the resume point.
    pub async fn read_existing_lines(
        &mut self,
        file: &Path,
        tx: &TokioSender<TailEvent>,
    ) -> Result<(), SentinelError> {
        let content = tokio::fs::read_to_string(file).await?;
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

        self.positions.insert(file.to_path_buf(), offset);
        Ok(())
    }

    /// Find and read all matching, non-rotated log files in a watched
    /// directory (initial discovery).
    pub async fn discover_existing_logs(
        &mut self,
        cfg: &LogWatchConfig,
        tx: &TokioSender<TailEvent>,
    ) -> Result<(), SentinelError> {
        let mut entries = tokio::fs::read_dir(&cfg.directory).await?;

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

            if self.tailed_files.insert(path.clone())
                && let Err(e) = self.read_existing_lines(&path, tx).await
            {
                warn!("failed to read existing lines from {:?}: {e}", path);
            }
        }

        Ok(())
    }

    /// React to one file-system event:
    /// - data modification on a tailed file → read the new bytes
    /// - creation of a matching file → adopt it (after it stabilises)
    /// - removal/rename to a rotated name → forget it
    pub async fn handle_event(
        &mut self,
        event: Event,
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
            ) && self.tailed_files.contains(&path)
            {
                if let Some(&pos) = self.positions.get(&path) {
                    let mut file = File::open(&path).await?;

                    file.seek(SeekFrom::Start(pos)).await?;

                    let mut new_content = String::new();
                    file.read_to_string(&mut new_content).await?;

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

                    self.positions.insert(path.clone(), current_offset);
                }
            } else if matches!(event.kind, EventKind::Create(_)) && !is_rotated_log(file_name) {
                if let Some(cfg) = find_matching_config(&path, watch_configs, watched_dirs)
                    && matches_pattern(&path, &cfg.pattern)
                {
                    self.tailed_files.insert(path.clone());
                    self.positions.insert(path.clone(), 0);

                    wait_for_file_stability(&path).await;

                    if let Err(e) = self.read_existing_lines(&path, tx).await {
                        warn!("failed to read newly created file {:?}: {e}", path);
                    }
                }
            } else if matches!(event.kind, EventKind::Remove(_))
                || (matches!(
                    event.kind,
                    EventKind::Modify(notify::event::ModifyKind::Name(_))
                ) && is_rotated_log(file_name))
            {
                self.positions.remove(&path);
                self.tailed_files.remove(&path);
            }
        }

        Ok(())
    }
}

/// Glob match against the file name only (never the directory part).
fn matches_pattern(path: &Path, pattern: &Pattern) -> bool {
    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
        pattern.matches(file_name)
    } else {
        false
    }
}

/// A write may still be in flight when the create event arrives; wait
/// until the size stops changing (or give up after a bounded number of
/// checks).
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
    fn test_find_matching_config_prefers_watched_dir() {
        let dir = PathBuf::from("/var/log/nginx");
        let cfgs = vec![LogWatchConfig::new(dir.clone(), "*.log").unwrap()];
        let watched = HashSet::from([dir.clone()]);

        let hit = find_matching_config(&dir.join("app.log"), &cfgs, &watched);
        assert!(hit.is_some());

        // A path outside the watched dir does not match.
        let miss = find_matching_config(&PathBuf::from("/var/log/other/app.log"), &cfgs, &watched);
        assert!(miss.is_none());
    }
}
