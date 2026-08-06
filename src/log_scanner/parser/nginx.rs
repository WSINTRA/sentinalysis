use super::{LogLevel, LogMetadata, LogParser, ParseError, ParsedLogEntry};
use chrono::{DateTime, FixedOffset, Utc};
use regex::Regex;
use std::sync::LazyLock;

pub struct NginxAccessParser;

impl NginxAccessParser {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for NginxAccessParser {
    fn default() -> Self {
        Self::new()
    }
}

static NGINX_COMBINED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^(?P<remote_addr>\S+) \S+ \S+ \[(?P<time_local>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<body_bytes_sent>\d+) "(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"$"#,
    )
    .unwrap()
});

impl LogParser for NginxAccessParser {
    fn parse(&self, line: &str) -> Result<Option<ParsedLogEntry>, ParseError> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(None);
        }

        let caps = NGINX_COMBINED_RE
            .captures(line)
            .ok_or(ParseError::InvalidFormat(
                "line does not match nginx combined format".to_string(),
            ))?;

        let remote_addr = caps
            .name("remote_addr")
            .and_then(|m| m.as_str().parse().ok())
            .ok_or(ParseError::InvalidValue {
                field: "remote_addr".to_string(),
                value: caps.name("remote_addr").unwrap().as_str().to_string(),
            })?;

        let timestamp = parse_nginx_timestamp(caps.name("time_local").unwrap().as_str())?;

        let request_parts: Vec<&str> = caps
            .name("request")
            .unwrap()
            .as_str()
            .splitn(3, ' ')
            .collect();

        let (method, path) = if request_parts.len() >= 2 {
            (
                Some(request_parts[0].to_string()),
                Some(request_parts[1].to_string()),
            )
        } else {
            (None, None)
        };

        let status: u16 = caps.name("status").unwrap().as_str().parse().map_err(|_| {
            ParseError::InvalidValue {
                field: "status".to_string(),
                value: caps.name("status").unwrap().as_str().to_string(),
            }
        })?;

        let bytes_sent: u64 = caps
            .name("body_bytes_sent")
            .unwrap()
            .as_str()
            .parse()
            .map_err(|_| ParseError::InvalidValue {
                field: "body_bytes_sent".to_string(),
                value: caps.name("body_bytes_sent").unwrap().as_str().to_string(),
            })?;

        let level = classify_status(status);

        let virtual_host = extract_virtual_host(path.clone());

        let metadata = LogMetadata {
            client_ip: Some(remote_addr),
            request_method: method,
            request_path: path.clone(),
            status_code: Some(status),
            bytes_sent: Some(bytes_sent),
            response_time_ms: None,
            user_agent: Some(caps.name("http_user_agent").unwrap().as_str().to_string()),
            referer: Some(caps.name("http_referer").unwrap().as_str().to_string()),
            virtual_host,
            upstream_service: None,
        };

        Ok(Some(ParsedLogEntry {
            timestamp,
            source_name: "nginx-access".to_string(),
            level,
            message: format!(
                "{} {} {}",
                metadata.request_method.as_deref().unwrap_or(""),
                metadata.request_path.as_deref().unwrap_or(""),
                status
            ),
            raw: line.to_string(),
            metadata,
        }))
    }

    fn name(&self) -> &'static str {
        "nginx_combined"
    }
}

fn parse_nginx_timestamp(s: &str) -> Result<DateTime<Utc>, ParseError> {
    DateTime::<FixedOffset>::parse_from_str(s, "%d/%b/%Y:%H:%M:%S %z")
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| ParseError::InvalidValue {
            field: "time_local".to_string(),
            value: s.to_string(),
        })
}

fn classify_status(status: u16) -> LogLevel {
    match status {
        100..=399 => LogLevel::Info,
        500..=599 => LogLevel::Error,
        _ => LogLevel::Warn,
    }
}

fn extract_virtual_host(_path: Option<String>) -> Option<String> {
    // Virtual host is typically extracted from the $host variable in nginx logs.
    // In combined format without $host, we'd need it in a custom log format.
    // For now, return None - will be populated from nginx error logs or config.
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;
    use rstest::rstest;
    use std::net::IpAddr;

    #[test]
    fn test_name_returns_nginx_combined() {
        let parser = NginxAccessParser::new();
        assert_eq!(parser.name(), "nginx_combined");
    }

    #[test]
    fn test_parse_empty_line_returns_none() {
        let parser = NginxAccessParser::new();
        let result = parser.parse("").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_whitespace_line_returns_none() {
        let parser = NginxAccessParser::new();
        let result = parser.parse("   ").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_valid_combined_log_format() {
        let parser = NginxAccessParser::new();
        let line = "192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] \"GET /api/health HTTP/1.1\" 200 15 \"-\" \"curl/8.0\"";
        let entry = parser.parse(line).unwrap().unwrap();

        assert_eq!(
            entry.metadata.client_ip,
            Some(IpAddr::from([192, 168, 1, 1]))
        );
        assert_eq!(entry.metadata.request_method, Some("GET".to_string()));
        assert_eq!(entry.metadata.request_path, Some("/api/health".to_string()));
        assert_eq!(entry.metadata.status_code, Some(200));
        assert_eq!(entry.metadata.bytes_sent, Some(15));
        assert_eq!(entry.metadata.user_agent, Some("curl/8.0".to_string()));
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.source_name, "nginx-access");
    }

    #[test]
    fn test_parse_ipv6_address() {
        let parser = NginxAccessParser::new();
        let line =
            "::1 - - [01/Jan/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 100 \"-\" \"Mozilla/5.0\"";
        let entry = parser.parse(line).unwrap().unwrap();

        assert_eq!(
            entry.metadata.client_ip,
            Some(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]))
        );
    }

    #[test]
    fn test_parse_500_status_is_error_level() {
        let parser = NginxAccessParser::new();
        let line =
            "10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] \"GET /fail HTTP/1.1\" 500 0 \"-\" \"test\"";
        let entry = parser.parse(line).unwrap().unwrap();

        assert_eq!(entry.level, LogLevel::Error);
        assert_eq!(entry.metadata.status_code, Some(500));
    }

    #[test]
    fn test_parse_404_status_is_warn_level() {
        let parser = NginxAccessParser::new();
        let line = "10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] \"GET /missing HTTP/1.1\" 404 0 \"-\" \"test\"";
        let entry = parser.parse(line).unwrap().unwrap();

        assert_eq!(entry.level, LogLevel::Warn);
        assert_eq!(entry.metadata.status_code, Some(404));
    }

    #[test]
    fn test_parse_301_status_is_info_level() {
        let parser = NginxAccessParser::new();
        let line =
            "10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] \"GET /old HTTP/1.1\" 301 0 \"-\" \"test\"";
        let entry = parser.parse(line).unwrap().unwrap();

        assert_eq!(entry.level, LogLevel::Info);
    }

    #[test]
    fn test_parse_with_referer() {
        let parser = NginxAccessParser::new();
        let line = "10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] \"GET /page HTTP/1.1\" 200 100 \"https://example.com\" \"Mozilla/5.0\"";
        let entry = parser.parse(line).unwrap().unwrap();

        assert_eq!(
            entry.metadata.referer,
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn test_parse_timestamp_with_timezone() {
        let parser = NginxAccessParser::new();
        let line =
            "10.0.0.1 - - [15/Mar/2025:10:30:45 +0530] \"GET / HTTP/1.1\" 200 10 \"-\" \"test\"";
        let entry = parser.parse(line).unwrap().unwrap();

        // 10:30:45 +0530 = 05:00:45 UTC
        assert_eq!(entry.timestamp.hour(), 5);
        assert_eq!(entry.timestamp.minute(), 0);
        assert_eq!(entry.timestamp.second(), 45);
    }

    #[test]
    fn test_parse_invalid_format_returns_error() {
        let parser = NginxAccessParser::new();
        let result = parser.parse("this is not a valid log line");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_ip_returns_error() {
        let parser = NginxAccessParser::new();
        let line =
            "not-an-ip - - [01/Jan/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 10 \"-\" \"test\"";
        let result = parser.parse(line);
        assert!(result.is_err());
    }

    #[rstest]
    #[case("GET")]
    #[case("POST")]
    #[case("PUT")]
    #[case("DELETE")]
    #[case("PATCH")]
    #[case("HEAD")]
    #[case("OPTIONS")]
    fn test_parse_various_http_methods(#[case] method: &str) {
        let parser = NginxAccessParser::new();
        let line = format!(
            r#"10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] "{} /test HTTP/1.1" 200 10 "-" "test""#,
            method
        );
        let entry = parser.parse(&line).unwrap().unwrap();
        assert_eq!(entry.metadata.request_method, Some(method.to_string()));
    }

    #[test]
    fn test_parse_large_body_bytes() {
        let parser = NginxAccessParser::new();
        let line = "10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] \"GET /file HTTP/1.1\" 200 999999999 \"-\" \"test\"";
        let entry = parser.parse(line).unwrap().unwrap();
        assert_eq!(entry.metadata.bytes_sent, Some(999999999));
    }

    #[test]
    fn test_parse_preserves_raw_line() {
        let parser = NginxAccessParser::new();
        let line =
            "10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 10 \"-\" \"test\"";
        let entry = parser.parse(line).unwrap().unwrap();
        assert_eq!(entry.raw, line);
    }

    #[test]
    fn test_message_contains_request_info() {
        let parser = NginxAccessParser::new();
        let line = "10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] \"GET /api/users HTTP/1.1\" 200 100 \"-\" \"test\"";
        let entry = parser.parse(line).unwrap().unwrap();
        assert!(entry.message.contains("GET"));
        assert!(entry.message.contains("/api/users"));
        assert!(entry.message.contains("200"));
    }
}
