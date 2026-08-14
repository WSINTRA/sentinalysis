//! Central error type for the whole crate.
//!
//! Every fallible operation returns `Result<T, SentinelError>`. Errors from
//! external libraries (I/O, Postgres, the file watcher, YAML) are kept as
//! source errors via `#[source]`, so `std::error::Error::source()` exposes
//! the full chain when logging or debugging.

use thiserror::Error;

/// The single error type propagated across module boundaries.
///
/// Wraps library errors where one exists (`Io`, `DatabaseError`,
/// `FileTailingError`); every other failure carries a human-readable
/// message describing what went wrong and where.
#[derive(Debug, Error)]
pub enum SentinelError {
    /// A log line could not be parsed by any `LogParser`.
    #[error("parse error: {0}")]
    ParseError(String),

    /// Filesystem or terminal I/O failure.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Postgres failure (connection, query, or migration).
    #[error("database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    /// Configuration is missing, unreadable, or invalid.
    #[error("config error: {0}")]
    ConfigError(String),

    /// Authentication or authorization failure (API layer).
    #[error("auth error: {0}")]
    AuthError(String),

    /// The `notify` file watcher failed (e.g. inotify limit reached).
    #[error("file tailing error: {0}")]
    FileTailingError(#[from] notify::Error),

    /// Interaction with a system service (systemd, daemon process) failed.
    #[error("service error: {0}")]
    ServiceError(String),

    /// Invariant violation or bug; should not happen in normal operation.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Lossy UTF-8 conversion failures are surfaced as invalid-data I/O errors,
/// preserving the original error in the source chain.
impl From<std::string::FromUtf8Error> for SentinelError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        SentinelError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }
}

/// YAML parse errors are configuration errors by definition.
impl From<serde_yaml::Error> for SentinelError {
    fn from(err: serde_yaml::Error) -> Self {
        SentinelError::ConfigError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_parse_error_display() {
        let err = SentinelError::ParseError("invalid log line".to_string());
        assert_eq!(err.to_string(), "parse error: invalid log line");
    }

    #[test]
    fn test_io_error_from_std_io() {
        let std_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: SentinelError = std_err.into();
        assert!(err.to_string().contains("file not found"));
        // The original io::Error is preserved in the source chain.
        assert!(err.source().is_some());
    }

    #[test]
    fn test_from_utf8_error_becomes_io() {
        let bad: Vec<u8> = vec![0xff, 0xfe];
        let err = String::from_utf8(bad).unwrap_err();
        let err: SentinelError = err.into();
        match err {
            SentinelError::Io(io_err) => {
                assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidData);
            }
            _ => panic!("Expected Io"),
        }
    }

    #[tokio::test]
    async fn test_database_error_display_and_source() {
        // A real (fast-failing) connection error gives us a sqlx::Error
        // without needing a live database.
        let pool = sqlx::PgPool::connect_lazy("postgresql://invalid:5432/none").unwrap();
        let sqlx_err = sqlx::query("SELECT 1").fetch_one(&pool).await.unwrap_err();
        let err: SentinelError = sqlx_err.into();
        assert!(err.to_string().starts_with("database error: "));
        assert!(err.source().is_some());
    }

    #[test]
    fn test_config_error_display() {
        let err = SentinelError::ConfigError("missing field".to_string());
        assert_eq!(err.to_string(), "config error: missing field");
    }

    #[test]
    fn test_auth_error_display() {
        let err = SentinelError::AuthError("invalid token".to_string());
        assert_eq!(err.to_string(), "auth error: invalid token");
    }

    #[test]
    fn test_file_tailing_error_display() {
        let err = SentinelError::FileTailingError(notify::Error::generic("inotify watch failed"));
        assert!(err.to_string().contains("inotify watch failed"));
        assert!(err.source().is_some());
    }

    #[test]
    fn test_service_error_display() {
        let err = SentinelError::ServiceError("systemctl failed".to_string());
        assert_eq!(err.to_string(), "service error: systemctl failed");
    }

    #[test]
    fn test_error_source_chain() {
        let err = SentinelError::ParseError("test".to_string());
        assert!(err.source().is_none());
    }

    #[test]
    fn test_error_debug_format() {
        let err = SentinelError::ParseError("test".to_string());
        let debug = format!("{err:?}");
        assert!(debug.contains("ParseError"));
    }
}
