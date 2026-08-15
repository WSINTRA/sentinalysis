//! Discover log sources from the configured watch targets.
//!
//! `SourceDiscovery` is the single place that knows how to turn a
//! `LogWatchingConfig` into the list of sources the daemon tails and the
//! TUI lists:
//! - a directory entry contributes a *vhost* source for every matching
//!   `<vhost>-access.log` file and a *system log* source for a matching
//!   `access.log` file;
//! - a file entry contributes a *system log* source when the file exists.
//!
//! Results are deduplicated and returned vhosts first, then system logs,
//! each group sorted by name.

use std::collections::BTreeSet;
use std::path::PathBuf;

use glob::Pattern;

use crate::config::LogWatchingConfig;
use crate::log_scanner::source::{Source, is_rotated_log, vhost_from_file_path};

/// Turns a `LogWatchingConfig` into discovered [`Source`]s.
#[derive(Debug, Clone)]
pub struct SourceDiscovery {
    directories: Vec<crate::config::LogDirectoryConfig>,
    files: Vec<PathBuf>,
}

impl SourceDiscovery {
    #[must_use]
    pub fn from_config(config: &LogWatchingConfig) -> Self {
        Self {
            directories: config.directories.clone(),
            files: config.files.clone(),
        }
    }

    /// Discover all sources. Missing directories and files are skipped
    /// (a config may name targets that do not exist on this host).
    pub fn discover(&self) -> Vec<Source> {
        let mut vhosts: BTreeSet<String> = BTreeSet::new();
        let mut system_logs: BTreeSet<String> = BTreeSet::new();

        for dir in &self.directories {
            Self::discover_directory(dir, &mut vhosts, &mut system_logs);
        }

        for file in &self.files {
            if file.is_file()
                && let Some(name) = file.file_name().and_then(|n| n.to_str())
            {
                system_logs.insert(name.to_string());
            }
        }

        let mut sources: Vec<Source> = vhosts.into_iter().map(Source::vhost).collect();
        sources.extend(system_logs.into_iter().map(Source::system_log));
        sources
    }

    fn discover_directory(
        dir: &crate::config::LogDirectoryConfig,
        vhosts: &mut BTreeSet<String>,
        system_logs: &mut BTreeSet<String>,
    ) {
        let Ok(entries) = std::fs::read_dir(&dir.path) else {
            return;
        };
        // Invalid patterns were already rejected when the tailer was
        // built; skip them here rather than failing discovery.
        let Ok(pattern) = Pattern::new(&dir.pattern) else {
            return;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !pattern.matches(file_name) || is_rotated_log(file_name) {
                continue;
            }
            if let Some(vhost) = vhost_from_file_path(&path) {
                vhosts.insert(vhost);
            } else if file_name == "access.log" {
                system_logs.insert("access.log".to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogDirectoryConfig;
    use std::path::Path;
    use tempfile::TempDir;

    fn discovery(dirs: Vec<LogDirectoryConfig>, files: Vec<PathBuf>) -> SourceDiscovery {
        SourceDiscovery::from_config(&crate::config::LogWatchingConfig {
            directories: dirs,
            files,
        })
    }

    fn dir_config(path: &Path, pattern: &str) -> LogDirectoryConfig {
        LogDirectoryConfig {
            path: path.to_path_buf(),
            pattern: pattern.to_string(),
        }
    }

    #[test]
    fn test_discover_vhosts_from_directory() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("api.example.com-access.log"), "").unwrap();
        std::fs::write(dir.path().join("shop.example.com-access.log"), "").unwrap();

        let sources = discovery(vec![dir_config(dir.path(), "*.log")], vec![]).discover();

        assert_eq!(
            sources,
            vec![
                Source::vhost("api.example.com"),
                Source::vhost("shop.example.com"),
            ]
        );
    }

    #[test]
    fn test_discover_ignores_rotated_and_unrelated_logs() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("app.example.com-access.log.1"), "").unwrap();
        std::fs::write(dir.path().join("app.example.com-error.log"), "").unwrap();
        std::fs::write(dir.path().join("random.log"), "").unwrap();

        let sources = discovery(vec![dir_config(dir.path(), "*.log")], vec![]).discover();

        assert!(sources.is_empty());
    }

    #[test]
    fn test_discover_system_logs_from_directory_and_files() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("access.log"), "").unwrap();
        let auth = dir.path().join("auth.log");
        std::fs::write(&auth, "").unwrap();

        let sources = discovery(vec![dir_config(dir.path(), "*.log")], vec![auth]).discover();

        assert_eq!(
            sources,
            vec![
                Source::system_log("access.log"),
                Source::system_log("auth.log"),
            ]
        );
    }

    #[test]
    fn test_discover_orders_vhosts_first_and_deduplicates() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("z.example.com-access.log"), "").unwrap();
        std::fs::write(dir.path().join("a.example.com-access.log"), "").unwrap();
        std::fs::write(dir.path().join("auth.log"), "").unwrap();

        // The configured auth.log file is listed twice: deduplicated.
        let auth = dir.path().join("auth.log");
        let sources = discovery(
            vec![dir_config(dir.path(), "*.log")],
            vec![auth.clone(), auth],
        )
        .discover();

        assert_eq!(
            sources,
            vec![
                Source::vhost("a.example.com"),
                Source::vhost("z.example.com"),
                Source::system_log("auth.log"),
            ]
        );
    }

    #[test]
    fn test_discover_respects_glob_pattern() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("app.example.com-access.log"), "").unwrap();
        std::fs::write(dir.path().join("app.example.com-error.log"), "").unwrap();

        let sources = discovery(vec![dir_config(dir.path(), "*-access.log")], vec![]).discover();

        assert_eq!(sources, vec![Source::vhost("app.example.com")]);
    }

    #[test]
    fn test_discover_missing_targets_are_skipped() {
        let sources = discovery(
            vec![dir_config(Path::new("/nonexistent/sentinel-test"), "*.log")],
            vec![PathBuf::from("/nonexistent/sentinel-test/auth.log")],
        )
        .discover();

        assert!(sources.is_empty());
    }

    #[test]
    fn test_discover_from_default_config_shape() {
        // The default config watches /var/log/nginx/*.log plus
        // /var/log/auth.log; whatever exists on this host must map to the
        // right kinds without panicking.
        let sources =
            SourceDiscovery::from_config(&crate::config::LogWatchingConfig::default()).discover();
        for source in &sources {
            if source.name == "access.log" || source.name == "auth.log" {
                assert_eq!(
                    source.kind,
                    crate::log_scanner::source::SourceKind::SystemLog
                );
            } else {
                assert_eq!(source.kind, crate::log_scanner::source::SourceKind::Vhost);
            }
        }
    }
}
