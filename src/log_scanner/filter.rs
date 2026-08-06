use crate::log_scanner::parser::ParsedLogEntry;
use regex::Regex;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct NoiseFilter {
    excluded_ips: Vec<IpAddr>,
    static_asset_patterns: Arc<Regex>,
    bot_user_agents: Vec<Arc<Regex>>,
    scanner_paths: Arc<Regex>,
}

impl NoiseFilter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            excluded_ips: vec![IpAddr::from([127, 0, 0, 1])],
            static_asset_patterns: Arc::new(
                Regex::new(r"\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$")
                    .expect("hardcoded static asset regex must be valid"),
            ),
            bot_user_agents: vec![
                Arc::new(
                    Regex::new(r"Googlebot").expect("hardcoded Googlebot regex must be valid"),
                ),
                Arc::new(Regex::new(r"Bingbot").expect("hardcoded Bingbot regex must be valid")),
                Arc::new(
                    Regex::new(r"YandexBot").expect("hardcoded YandexBot regex must be valid"),
                ),
                Arc::new(Regex::new(r"Slurp").expect("hardcoded Slurp regex must be valid")),
                Arc::new(
                    Regex::new(r"DuckDuckBot").expect("hardcoded DuckDuckBot regex must be valid"),
                ),
            ],
            scanner_paths: Arc::new(
                Regex::new(
                    r"(/wp-admin|/wp-login|/phpmyadmin|/\.env|/\.git|/admin\.php|/xmlrpc\.php)",
                )
                .expect("hardcoded scanner paths regex must be valid"),
            ),
        }
    }

    #[must_use]
    pub fn with_excluded_ips(mut self, ips: Vec<IpAddr>) -> Self {
        self.excluded_ips = ips;
        self
    }

    #[must_use]
    pub fn evaluate(&self, entry: &ParsedLogEntry) -> FilterResult {
        // Check excluded IPs first
        if let Some(ip) = &entry.metadata.client_ip
            && self.excluded_ips.contains(ip)
        {
            return FilterResult::Exclude("excluded IP".to_string());
        }

        // Check for scanner/reconnaissance paths
        if let Some(ref path) = entry.metadata.request_path
            && self.scanner_paths.is_match(path)
        {
            return FilterResult::FlagSecurity(format!("scanner path: {path}"));
        }

        // Check for static assets
        if let Some(ref path) = entry.metadata.request_path
            && self.static_asset_patterns.is_match(path)
        {
            return FilterResult::Aggregate("static asset".to_string());
        }

        // Check for known bots
        if let Some(ref ua) = entry.metadata.user_agent {
            for bot_pattern in &self.bot_user_agents {
                if bot_pattern.is_match(ua) {
                    return FilterResult::Aggregate(format!("bot: {ua}"));
                }
            }
        }

        // Check for security patterns in request
        if let Some(ref path) = entry.metadata.request_path {
            if Self::is_sql_injection(path) {
                return FilterResult::FlagSecurity("SQL injection attempt".to_string());
            }
            if Self::is_path_traversal(path) {
                return FilterResult::FlagSecurity("path traversal attempt".to_string());
            }
        }

        FilterResult::Keep
    }

    #[must_use]
    fn is_sql_injection(path: &str) -> bool {
        let path_lower = path.to_lowercase();
        path_lower.contains("union select")
            || path_lower.contains("' or '")
            || path_lower.contains("1=1")
            || path_lower.contains("drop table")
    }

    #[must_use]
    fn is_path_traversal(path: &str) -> bool {
        path.contains("../") || path.contains("..\\")
    }
}

impl Default for NoiseFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterResult {
    Keep,
    Exclude(String),
    Aggregate(String),
    FlagSecurity(String),
}

impl FilterResult {
    #[must_use]
    pub fn should_store(&self) -> bool {
        !matches!(self, FilterResult::Exclude(_))
    }

    #[must_use]
    pub fn is_security_flag(&self) -> bool {
        matches!(self, FilterResult::FlagSecurity(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_scanner::parser::{LogLevel, LogMetadata, ParsedLogEntry};
    use chrono::Utc;
    use rstest::rstest;
    use std::net::IpAddr;

    fn make_entry(ip: IpAddr, path: &str, ua: &str, status: u16) -> ParsedLogEntry {
        ParsedLogEntry {
            timestamp: Utc::now(),
            source_name: "nginx-access".to_string(),
            level: if status >= 500 {
                LogLevel::Error
            } else {
                LogLevel::Info
            },
            message: format!("GET {path} {status}"),
            raw: "".to_string(),
            metadata: LogMetadata {
                client_ip: Some(ip),
                request_method: Some("GET".to_string()),
                request_path: Some(path.to_string()),
                status_code: Some(status),
                bytes_sent: Some(100),
                response_time_ms: None,
                user_agent: Some(ua.to_string()),
                referer: None,
                virtual_host: None,
                upstream_service: None,
            },
        }
    }

    #[test]
    fn test_new_has_default_excluded_ips() {
        let filter = NoiseFilter::new();
        let entry = make_entry(
            IpAddr::from([127, 0, 0, 1]),
            "/api/health",
            "HealthChecker/1.0",
            200,
        );
        assert_eq!(
            filter.evaluate(&entry),
            FilterResult::Exclude("excluded IP".to_string())
        );
    }

    #[test]
    fn test_custom_excluded_ips() {
        let filter = NoiseFilter::new().with_excluded_ips(vec![
            IpAddr::from([10, 0, 0, 1]),
            IpAddr::from([10, 0, 0, 2]),
        ]);
        let entry = make_entry(IpAddr::from([10, 0, 0, 1]), "/api/data", "curl/8.0", 200);
        assert_eq!(
            filter.evaluate(&entry),
            FilterResult::Exclude("excluded IP".to_string())
        );
    }

    #[test]
    fn test_static_asset_css_aggregated() {
        let filter = NoiseFilter::new();
        let entry = make_entry(
            IpAddr::from([192, 168, 1, 1]),
            "/styles/main.css",
            "Mozilla/5.0",
            200,
        );
        assert_eq!(
            filter.evaluate(&entry),
            FilterResult::Aggregate("static asset".to_string())
        );
    }

    #[rstest]
    #[case("/scripts/app.js")]
    #[case("/images/logo.png")]
    #[case("/fonts/roboto.woff2")]
    #[case("/icons/favicon.ico")]
    #[case("/img/photo.jpg")]
    fn test_static_asset_various_extensions_aggregated(#[case] path: &str) {
        let filter = NoiseFilter::new();
        let entry = make_entry(IpAddr::from([192, 168, 1, 1]), path, "Mozilla/5.0", 200);
        assert_eq!(
            filter.evaluate(&entry),
            FilterResult::Aggregate("static asset".to_string())
        );
    }

    #[test]
    fn test_googlebot_aggregated() {
        let filter = NoiseFilter::new();
        let entry = make_entry(
            IpAddr::from([66, 249, 65, 1]),
            "/page",
            "Mozilla/5.0 (compatible; Googlebot/2.1)",
            200,
        );
        assert_eq!(
            filter.evaluate(&entry),
            FilterResult::Aggregate("bot: Mozilla/5.0 (compatible; Googlebot/2.1)".to_string())
        );
    }

    #[rstest]
    #[case("Mozilla/5.0 (compatible; Bingbot/2.0)")]
    #[case("Mozilla/5.0 (compatible; YandexBot/3.0)")]
    fn test_various_bots_aggregated(#[case] ua: &str) {
        let filter = NoiseFilter::new();
        let entry = make_entry(IpAddr::from([192, 168, 1, 1]), "/", ua, 200);
        assert!(matches!(
            filter.evaluate(&entry),
            FilterResult::Aggregate(_)
        ));
    }

    #[test]
    fn test_wp_admin_scanner_flagged() {
        let filter = NoiseFilter::new();
        let entry = make_entry(IpAddr::from([192, 168, 1, 1]), "/wp-admin", "curl/8.0", 404);
        assert_eq!(
            filter.evaluate(&entry),
            FilterResult::FlagSecurity("scanner path: /wp-admin".to_string())
        );
    }

    #[rstest]
    #[case("/wp-login.php")]
    #[case("/phpmyadmin")]
    #[case("/.env")]
    #[case("/.git/config")]
    #[case("/xmlrpc.php")]
    fn test_various_scanner_paths_flagged(#[case] path: &str) {
        let filter = NoiseFilter::new();
        let entry = make_entry(IpAddr::from([192, 168, 1, 1]), path, "scanner/1.0", 404);
        assert!(matches!(
            filter.evaluate(&entry),
            FilterResult::FlagSecurity(_)
        ));
    }

    #[test]
    fn test_sql_injection_flagged() {
        let filter = NoiseFilter::new();
        let entry = make_entry(
            IpAddr::from([192, 168, 1, 1]),
            "/api/users?id=1 UNION SELECT * FROM passwords",
            "curl/8.0",
            400,
        );
        assert_eq!(
            filter.evaluate(&entry),
            FilterResult::FlagSecurity("SQL injection attempt".to_string())
        );
    }

    #[rstest]
    #[case("/api?id=' or '1'='1")]
    #[case("/api?drop table users")]
    fn test_various_sql_injection_flagged(#[case] path: &str) {
        let filter = NoiseFilter::new();
        let entry = make_entry(IpAddr::from([192, 168, 1, 1]), path, "curl/8.0", 400);
        assert!(matches!(
            filter.evaluate(&entry),
            FilterResult::FlagSecurity(_)
        ));
    }

    #[test]
    fn test_path_traversal_flagged() {
        let filter = NoiseFilter::new();
        let entry = make_entry(
            IpAddr::from([192, 168, 1, 1]),
            "/files/../../../etc/passwd",
            "curl/8.0",
            403,
        );
        assert_eq!(
            filter.evaluate(&entry),
            FilterResult::FlagSecurity("path traversal attempt".to_string())
        );
    }

    #[test]
    fn test_normal_request_kept() {
        let filter = NoiseFilter::new();
        let entry = make_entry(
            IpAddr::from([192, 168, 1, 100]),
            "/api/users",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            200,
        );
        assert_eq!(filter.evaluate(&entry), FilterResult::Keep);
    }

    #[test]
    fn test_exclude_should_not_store() {
        assert!(!FilterResult::Exclude("reason".to_string()).should_store());
    }

    #[test]
    fn test_keep_should_store() {
        assert!(FilterResult::Keep.should_store());
    }

    #[test]
    fn test_aggregate_should_store() {
        assert!(FilterResult::Aggregate("reason".to_string()).should_store());
    }

    #[test]
    fn test_flag_security_should_store() {
        assert!(FilterResult::FlagSecurity("reason".to_string()).should_store());
    }

    #[test]
    fn test_flag_security_is_security_flag() {
        assert!(FilterResult::FlagSecurity("reason".to_string()).is_security_flag());
        assert!(!FilterResult::Keep.is_security_flag());
    }
}
