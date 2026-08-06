use std::fmt;

#[derive(Debug)]
pub enum SentinelError {
    ParseError(String),
    Io(String),
    DatabaseError(String),
    ConfigError(String),
    AuthError(String),
    FileTailingError(String),
    ServiceError(String),
    Internal(String),
}

impl fmt::Display for SentinelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SentinelError::ParseError(msg) => write!(f, "parse error: {msg}"),
            SentinelError::Io(msg) => write!(f, "IO error: {msg}"),
            SentinelError::DatabaseError(msg) => write!(f, "database error: {msg}"),
            SentinelError::ConfigError(msg) => write!(f, "config error: {msg}"),
            SentinelError::AuthError(msg) => write!(f, "auth error: {msg}"),
            SentinelError::FileTailingError(msg) => write!(f, "file tailing error: {msg}"),
            SentinelError::ServiceError(msg) => write!(f, "service error: {msg}"),
            SentinelError::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for SentinelError {}

impl From<std::io::Error> for SentinelError {
    fn from(err: std::io::Error) -> Self {
        SentinelError::Io(err.to_string())
    }
}

impl From<std::string::FromUtf8Error> for SentinelError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        SentinelError::Io(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_parse_error_display() {
        let err = SentinelError::ParseError("invalid log line".to_string());
        assert!(err.to_string().contains("invalid log line"));
    }

    #[test]
    fn test_io_error_from_std_io() {
        let std_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: SentinelError = std_err.into();
        match err {
            SentinelError::Io(msg) => assert!(msg.contains("file not found")),
            _ => panic!("Expected Io"),
        }
    }

    #[test]
    fn test_database_error_display() {
        let err = SentinelError::DatabaseError("connection failed".to_string());
        assert!(err.to_string().contains("connection failed"));
    }

    #[test]
    fn test_config_error_display() {
        let err = SentinelError::ConfigError("missing field".to_string());
        assert!(err.to_string().contains("missing field"));
    }

    #[test]
    fn test_auth_error_display() {
        let err = SentinelError::AuthError("invalid token".to_string());
        assert!(err.to_string().contains("invalid token"));
    }

    #[test]
    fn test_file_tailing_error_display() {
        let err = SentinelError::FileTailingError("inotify watch failed".to_string());
        assert!(err.to_string().contains("inotify watch failed"));
    }

    #[test]
    fn test_service_error_display() {
        let err = SentinelError::ServiceError("systemctl failed".to_string());
        assert!(err.to_string().contains("systemctl failed"));
    }

    #[test]
    fn test_error_source_chain() {
        let err = SentinelError::ParseError("test".to_string());
        assert!(err.source().is_none());
    }

    #[test]
    fn test_error_debug_format() {
        let err = SentinelError::ParseError("test".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("ParseError"));
    }
}
