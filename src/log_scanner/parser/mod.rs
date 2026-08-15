//! Pluggable log-line parsers and the parsed-entry model they produce.
//!
//! A [`LogParser`] turns one raw line into a `Option<ParsedLogEntry>`
//! (`None` = the line does not belong to this format). Implementations:
//! nginx access logs ([`nginx`]) and syslog-style auth logs ([`auth`]).

use chrono::{DateTime, Utc};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedLogEntry {
    pub timestamp: DateTime<Utc>,
    pub source_name: String,
    pub level: LogLevel,
    pub message: String,
    pub raw: String,
    pub metadata: LogMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Critical,
    Security,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct LogMetadata {
    pub client_ip: Option<IpAddr>,
    pub request_method: Option<String>,
    pub request_path: Option<String>,
    pub status_code: Option<u16>,
    pub bytes_sent: Option<u64>,
    pub response_time_ms: Option<u64>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub virtual_host: Option<String>,
    pub upstream_service: Option<String>,
}

#[derive(Debug)]
pub enum ParseError {
    InvalidFormat(String),
    MissingField(String),
    InvalidValue { field: String, value: String },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::InvalidFormat(msg) => write!(f, "invalid format: {msg}"),
            ParseError::MissingField(field) => write!(f, "missing field: {field}"),
            ParseError::InvalidValue { field, value } => {
                write!(f, "invalid value for {field}: {value}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl LogLevel {
    /// The lowercase name stored in `log_entries.level`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
            LogLevel::Critical => "critical",
            LogLevel::Security => "security",
        }
    }

    /// Parse a stored level; unknown values map to [`LogLevel::Info`].
    #[must_use]
    pub fn from_db(value: &str) -> Self {
        match value {
            "debug" => LogLevel::Debug,
            "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            "critical" => LogLevel::Critical,
            "security" => LogLevel::Security,
            _ => LogLevel::Info,
        }
    }
}

pub trait LogParser: Send + Sync {
    fn parse(&self, line: &str) -> Result<Option<ParsedLogEntry>, ParseError>;
    fn name(&self) -> &str;
}

pub mod auth;
pub mod nginx;
