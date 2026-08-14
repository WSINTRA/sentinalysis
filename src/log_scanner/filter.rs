//! Noise filtering for parsed log entries.
//!
//! `NoiseFilter` decides what to do with a `ParsedLogEntry` before it is
//! stored: keep it, exclude it entirely, aggregate it (noise such as bots
//! or static assets), or flag it as a security event. The detection rules
//! come from `NoiseFilterConfig`; security *categorisation* (which kind of
//! attack) belongs to the `Classifier`, and this filter defers to it for
//! `SQLi` / path-traversal detection.

use crate::config::NoiseFilterConfig;
use crate::log_scanner::classifier::Classifier;
use crate::log_scanner::parser::ParsedLogEntry;
use regex::Regex;
use std::net::IpAddr;
use std::sync::Arc;

/// Evaluates parsed log entries against a set of noise rules.
///
/// Check order matters: earlier rules win, so cheap, unambiguous noise
/// (excluded IPs) is tested before expensive or overlapping ones.
#[derive(Debug, Clone)]
pub struct NoiseFilter {
    excluded_ips: Vec<IpAddr>,
    health_check_paths: Vec<String>,
    static_asset_pattern: Arc<Regex>,
    bot_user_agents: Vec<Arc<Regex>>,
    scanner_paths: Arc<Regex>,
    /// Shared classifier used to detect `SQLi` / path traversal in requests.
    classifier: Arc<Classifier>,
}

impl NoiseFilter {
    /// A filter built from the default `NoiseFilterConfig`.
    #[must_use]
    pub fn new() -> Self {
        Self::from_config(&NoiseFilterConfig::default())
    }

    /// Build a filter from user configuration. Extension and user-agent
    /// strings are escaped, so they are treated as literals, not patterns.
    #[must_use]
    pub fn from_config(config: &NoiseFilterConfig) -> Self {
        let static_asset_pattern = if config.static_asset_extensions.is_empty() {
            // Nothing to match.
            Arc::new(Regex::new(r"$^").expect("unmatchable regex is valid"))
        } else {
            let extensions = config
                .static_asset_extensions
                .iter()
                .map(|ext| {
                    let escaped = regex::escape(ext);
                    if ext.contains('.') {
                        // Multi-dot "extensions" (e.g. "manifest.json") are
                        // matched literally at the end of the path.
                        escaped
                    } else {
                        // A plain extension must be preceded by a dot so that
                        // "css" matches ".css" but not "bcss".
                        format!(r"\.{escaped}")
                    }
                })
                .collect::<Vec<_>>()
                .join("|");
            Arc::new(
                Regex::new(&format!("(?:{extensions})$"))
                    .expect("escaped extensions always form a valid regex"),
            )
        };

        let bot_user_agents = config
            .known_bot_user_agents
            .iter()
            .map(|ua| {
                Arc::new(
                    Regex::new(&regex::escape(ua))
                        .expect("escaped user agent string is a valid regex"),
                )
            })
            .collect();

        Self {
            excluded_ips: config.excluded_ips.clone(),
            health_check_paths: config.health_check_paths.clone(),
            static_asset_pattern,
            bot_user_agents,
            // Reconnaissance endpoints are a fixed, well-known set.
            scanner_paths: Arc::new(
                Regex::new(
                    r"(/wp-admin|/wp-login|/phpmyadmin|/\.env|/\.git|/admin\.php|/xmlrpc\.php)",
                )
                .expect("hardcoded scanner paths regex must be valid"),
            ),
            classifier: Arc::new(Classifier::new()),
        }
    }

    /// Replace the excluded IP list (builder style, mostly for tests).
    #[must_use]
    pub fn with_excluded_ips(mut self, ips: Vec<IpAddr>) -> Self {
        self.excluded_ips = ips;
        self
    }

    /// Evaluate an entry against the noise rules.
    #[must_use]
    pub fn evaluate(&self, entry: &ParsedLogEntry) -> FilterResult {
        // Health checkers and local monitoring are the most common noise.
        if let Some(ip) = &entry.metadata.client_ip
            && self.excluded_ips.contains(ip)
        {
            return FilterResult::Exclude("excluded IP".to_string());
        }

        if let Some(path) = &entry.metadata.request_path
            && self.health_check_paths.iter().any(|p| p == path)
        {
            return FilterResult::Aggregate("health check".to_string());
        }

        // Active reconnaissance against well-known endpoints is worth
        // surfacing even though it is not "interesting" log content.
        if let Some(ref path) = entry.metadata.request_path
            && self.scanner_paths.is_match(path)
        {
            return FilterResult::FlagSecurity(format!("scanner path: {path}"));
        }

        if let Some(ref path) = entry.metadata.request_path
            && self.static_asset_pattern.is_match(path)
        {
            return FilterResult::Aggregate("static asset".to_string());
        }

        if let Some(ref ua) = entry.metadata.user_agent {
            for bot_pattern in &self.bot_user_agents {
                if bot_pattern.is_match(ua) {
                    return FilterResult::Aggregate(format!("bot: {ua}"));
                }
            }
        }

        // Attack detection is owned by the classifier; the filter only
        // translates the result into a storage decision.
        let threat = self.classifier.classify(entry);
        if threat.categories.iter().any(|c| {
            matches!(
                c,
                crate::log_scanner::classifier::ThreatCategory::SqlInjection
                    | crate::log_scanner::classifier::ThreatCategory::PathTraversal
            )
        }) {
            return FilterResult::FlagSecurity("attack pattern in request".to_string());
        }

        FilterResult::Keep
    }
}

impl Default for NoiseFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// The storage decision for a parsed entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterResult {
    /// Store the entry as-is.
    Keep,
    /// Drop the entry entirely.
    Exclude(String),
    /// Store as noise (raw line suppressed).
    Aggregate(String),
    /// Store and mark as a security event.
    FlagSecurity(String),
}

impl FilterResult {
    /// Whether the entry should be persisted at all.
    #[must_use]
    pub fn should_store(&self) -> bool {
        !matches!(self, FilterResult::Exclude(_))
    }

    /// Whether the entry is flagged as a security event.
    #[must_use]
    pub fn is_security_flag(&self) -> bool {
        matches!(self, FilterResult::FlagSecurity(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_scanner::parser::{LogLevel, LogMetadata};
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
            raw: String::new(),
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
        assert!(matches!(
            filter.evaluate(&entry),
            FilterResult::FlagSecurity(_)
        ));
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
        assert!(matches!(
            filter.evaluate(&entry),
            FilterResult::FlagSecurity(_)
        ));
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

    // --- from_config: user-supplied rules actually take effect ---

    fn config_with(
        mut health: Vec<String>,
        mut extensions: Vec<String>,
        mut bots: Vec<String>,
    ) -> NoiseFilterConfig {
        if health.is_empty() {
            health = vec!["/health".to_string(), "/healthz".to_string()];
        }
        if extensions.is_empty() {
            extensions = vec!["css".to_string()];
        }
        if bots.is_empty() {
            bots = vec!["Googlebot".to_string()];
        }
        NoiseFilterConfig {
            excluded_ips: vec![],
            health_check_paths: health,
            static_asset_extensions: extensions,
            known_bot_user_agents: bots,
        }
    }

    #[test]
    fn test_from_config_health_check_path_aggregated() {
        let filter =
            NoiseFilter::from_config(&config_with(vec!["/ping".to_string()], vec![], vec![]));
        let entry = make_entry(IpAddr::from([192, 168, 1, 1]), "/ping", "curl/8.0", 200);
        assert_eq!(
            filter.evaluate(&entry),
            FilterResult::Aggregate("health check".to_string())
        );
    }

    #[test]
    fn test_from_config_health_check_path_is_exact_match() {
        let filter =
            NoiseFilter::from_config(&config_with(vec!["/ping".to_string()], vec![], vec![]));
        let entry = make_entry(IpAddr::from([192, 168, 1, 1]), "/api/ping", "curl/8.0", 200);
        assert_eq!(filter.evaluate(&entry), FilterResult::Keep);
    }

    #[test]
    fn test_from_config_empty_static_extensions_matches_nothing() {
        // A genuinely empty config (no defaulting helper in between).
        let config = NoiseFilterConfig {
            excluded_ips: vec![],
            health_check_paths: vec![],
            static_asset_extensions: vec![],
            known_bot_user_agents: vec![],
        };
        let filter = NoiseFilter::from_config(&config);
        let entry = make_entry(
            IpAddr::from([192, 168, 1, 1]),
            "/styles/main.css",
            "Mozilla/5.0",
            200,
        );
        assert_eq!(filter.evaluate(&entry), FilterResult::Keep);
    }

    #[test]
    fn test_from_config_custom_bot_user_agent() {
        let filter = NoiseFilter::from_config(&config_with(
            vec![],
            vec![],
            vec!["MyCrawler/1.0".to_string()],
        ));
        let entry = make_entry(
            IpAddr::from([192, 168, 1, 1]),
            "/page",
            "MyCrawler/1.0",
            200,
        );
        assert_eq!(
            filter.evaluate(&entry),
            FilterResult::Aggregate("bot: MyCrawler/1.0".to_string())
        );
    }

    #[test]
    fn test_from_config_excluded_ips() {
        let config = NoiseFilterConfig {
            excluded_ips: vec![IpAddr::from([10, 1, 1, 1])],
            ..config_with(vec![], vec![], vec![])
        };
        let filter = NoiseFilter::from_config(&config);
        let entry = make_entry(IpAddr::from([10, 1, 1, 1]), "/api/data", "curl/8.0", 200);
        assert_eq!(
            filter.evaluate(&entry),
            FilterResult::Exclude("excluded IP".to_string())
        );
    }
}
