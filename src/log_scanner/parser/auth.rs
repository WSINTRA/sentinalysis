use super::{LogLevel, LogMetadata, LogParser, ParseError, ParsedLogEntry};
use chrono::{DateTime, Datelike, Utc};
use regex::Regex;
use std::net::IpAddr;
use std::sync::LazyLock;

pub struct AuthLogParser;

impl AuthLogParser {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for AuthLogParser {
    fn default() -> Self {
        Self::new()
    }
}

static SYSLOG_TIMESTAMP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$",
    )
    .unwrap()
});

static SSH_FAILED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+")
        .unwrap()
});

static SSH_ACCEPTED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+")
        .unwrap()
});

impl LogParser for AuthLogParser {
    fn parse(&self, line: &str) -> Result<Option<ParsedLogEntry>, ParseError> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(None);
        }

        let caps = SYSLOG_TIMESTAMP_RE
            .captures(line)
            .ok_or(ParseError::InvalidFormat(
                "line does not match syslog format".to_string(),
            ))?;

        let timestamp = parse_syslog_timestamp(
            caps.name("month").unwrap().as_str(),
            caps.name("day").unwrap().as_str(),
            caps.name("time").unwrap().as_str(),
        )?;

        let message = caps.name("message").unwrap().as_str().to_string();
        let service = caps.name("service").unwrap().as_str().to_string();

        let (level, client_ip) = classify_auth_message(&message);

        let metadata = LogMetadata {
            client_ip,
            ..LogMetadata::default()
        };

        Ok(Some(ParsedLogEntry {
            timestamp,
            source_name: "auth-log".to_string(),
            level,
            message: format!("[{service}] {message}"),
            raw: line.to_string(),
            metadata,
        }))
    }

    fn name(&self) -> &'static str {
        "syslog"
    }
}

fn parse_syslog_timestamp(month: &str, day: &str, time: &str) -> Result<DateTime<Utc>, ParseError> {
    let year = Utc::now().year();
    let s = format!("{month} {day} {year} {time}");

    chrono::NaiveDateTime::parse_from_str(&s, "%b %d %Y %H:%M:%S")
        .map(|dt| dt.and_utc())
        .map_err(|_| ParseError::InvalidValue {
            field: "timestamp".to_string(),
            value: s,
        })
}

fn classify_auth_message(message: &str) -> (LogLevel, Option<IpAddr>) {
    if let Some(caps) = SSH_FAILED_RE.captures(message) {
        let ip = caps.name("ip").and_then(|m| m.as_str().parse().ok());
        return (LogLevel::Security, ip);
    }

    if let Some(caps) = SSH_ACCEPTED_RE.captures(message) {
        let ip = caps.name("ip").and_then(|m| m.as_str().parse().ok());
        return (LogLevel::Info, ip);
    }

    if message.contains("error") || message.contains("failed") {
        return (LogLevel::Error, None);
    }

    if message.contains("warning") || message.contains("invalid") {
        return (LogLevel::Warn, None);
    }

    (LogLevel::Info, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn test_name_returns_syslog() {
        let parser = AuthLogParser::new();
        assert_eq!(parser.name(), "syslog");
    }

    #[test]
    fn test_parse_empty_line_returns_none() {
        let parser = AuthLogParser::new();
        let result = parser.parse("").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_ssh_failed_login() {
        let parser = AuthLogParser::new();
        let line = "Jan 15 10:30:45 myhost sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2";
        let entry = parser.parse(line).unwrap().unwrap();

        assert_eq!(entry.level, LogLevel::Security);
        assert_eq!(
            entry.metadata.client_ip,
            Some(IpAddr::from([192, 168, 1, 100]))
        );
        assert!(entry.message.contains("sshd"));
        assert!(entry.message.contains("Failed password"));
    }

    #[test]
    fn test_parse_ssh_failed_invalid_user() {
        let parser = AuthLogParser::new();
        let line = "Jan 15 10:30:45 myhost sshd[1234]: Failed password for invalid user root from 10.0.0.1 port 22 ssh2";
        let entry = parser.parse(line).unwrap().unwrap();

        assert_eq!(entry.level, LogLevel::Security);
        assert_eq!(entry.metadata.client_ip, Some(IpAddr::from([10, 0, 0, 1])));
    }

    #[test]
    fn test_parse_ssh_accepted_login() {
        let parser = AuthLogParser::new();
        let line = "Jan 15 10:30:45 myhost sshd[1234]: Accepted publickey for deploy from 192.168.1.50 port 22 ssh2";
        let entry = parser.parse(line).unwrap().unwrap();

        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(
            entry.metadata.client_ip,
            Some(IpAddr::from([192, 168, 1, 50]))
        );
    }

    #[test]
    fn test_parse_ssh_accepted_password() {
        let parser = AuthLogParser::new();
        let line = "Jan 15 10:30:45 myhost sshd[1234]: Accepted password for user from 10.0.0.5 port 22 ssh2";
        let entry = parser.parse(line).unwrap().unwrap();

        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.metadata.client_ip, Some(IpAddr::from([10, 0, 0, 5])));
    }

    #[test]
    fn test_parse_generic_error_message() {
        let parser = AuthLogParser::new();
        let line = "Jan 15 10:30:45 myhost systemd[1]: Some error occurred";
        let entry = parser.parse(line).unwrap().unwrap();

        assert_eq!(entry.level, LogLevel::Error);
    }

    #[test]
    fn test_parse_generic_warning_message() {
        let parser = AuthLogParser::new();
        let line = "Jan 15 10:30:45 myhost kernel: warning: something";
        let entry = parser.parse(line).unwrap().unwrap();

        assert_eq!(entry.level, LogLevel::Warn);
    }

    #[test]
    fn test_parse_generic_info_message() {
        let parser = AuthLogParser::new();
        let line = "Jan 15 10:30:45 myhost systemd[1]: Started Service";
        let entry = parser.parse(line).unwrap().unwrap();

        assert_eq!(entry.level, LogLevel::Info);
    }

    #[test]
    fn test_parse_invalid_format_returns_error() {
        let parser = AuthLogParser::new();
        let result = parser.parse("not a syslog line");
        assert!(result.is_err());
    }

    #[rstest]
    #[case("Jan")]
    #[case("Feb")]
    #[case("Mar")]
    #[case("Dec")]
    fn test_parse_various_months(#[case] month: &str) {
        let parser = AuthLogParser::new();
        let line = format!(
            "{month} 15 10:30:45 myhost sshd[1234]: Accepted password for user from 10.0.0.1 port 22 ssh2"
        );
        let result = parser.parse(&line);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_preserves_raw_line() {
        let parser = AuthLogParser::new();
        let line = "Jan 15 10:30:45 myhost sshd[1234]: Test message";
        let entry = parser.parse(line).unwrap().unwrap();
        assert_eq!(entry.raw, line);
    }

    #[test]
    fn test_parse_source_name_is_auth_log() {
        let parser = AuthLogParser::new();
        let line = "Jan 15 10:30:45 myhost sshd[1234]: Test";
        let entry = parser.parse(line).unwrap().unwrap();
        assert_eq!(entry.source_name, "auth-log");
    }

    #[test]
    fn test_parse_message_includes_service() {
        let parser = AuthLogParser::new();
        let line = "Jan 15 10:30:45 myhost myservice[999]: Test message";
        let entry = parser.parse(line).unwrap().unwrap();
        assert!(entry.message.contains("[myservice]"));
    }
}
