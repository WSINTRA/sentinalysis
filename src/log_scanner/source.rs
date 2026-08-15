//! Log source model and the file-name conventions that define sources.
//!
//! A *source* is what the TUI lists in its sources panel: an nginx
//! virtual host (discovered from `<vhost>-access.log` files) or a plain
//! system log file (e.g. `auth.log`). The file-name rules live here so
//! that the scanner pipeline, the file tailer, and the TUI all agree on
//! what a file name means.

use std::path::Path;

/// The kind of log source, which also decides how entries are matched
/// against the `services` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// An nginx virtual host, matched on `services.virtual_host`.
    Vhost,
    /// A plain log file (e.g. `auth.log`), matched on `services.name`
    /// with no virtual host set.
    SystemLog,
}

/// One discoverable log source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub name: String,
    pub kind: SourceKind,
}

impl Source {
    #[must_use]
    pub fn vhost(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: SourceKind::Vhost,
        }
    }

    #[must_use]
    pub fn system_log(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: SourceKind::SystemLog,
        }
    }
}

/// Derive the virtual host from an nginx vhost access-log file name
/// (`<vhost>-access.log` → `<vhost>`). Rotated names
/// (`<vhost>-access.log.1`) are not vhost logs.
#[must_use]
pub fn vhost_from_file_path(file_path: &Path) -> Option<String> {
    file_path
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|name| name.ends_with("-access.log"))
        .map(|name| name.trim_end_matches("-access.log").to_string())
}

/// A rotated log has a purely numeric suffix: `access.log.1`. Gzipped
/// rotations (`access.log.1.gz`) are not tailed.
#[must_use]
pub fn is_rotated_log(file_name: &str) -> bool {
    if let Some(dot_pos) = file_name.rfind('.') {
        let suffix = &file_name[dot_pos + 1..];
        !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit())
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vhost_from_file_path() {
        assert_eq!(
            vhost_from_file_path(Path::new("/var/log/nginx/api.example.com-access.log")),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            vhost_from_file_path(Path::new("/var/log/nginx/access.log")),
            None
        );
        assert_eq!(
            vhost_from_file_path(Path::new("/var/log/nginx/app.example.com-access.log.1")),
            None
        );
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
}
