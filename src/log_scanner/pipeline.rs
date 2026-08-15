//! The per-line processing pipeline: parse → filter → classify → insert model.
//!
//! `Pipeline` is the heart of the daemon. It turns one raw `TailLine` into
//! a ready-to-store `InsertLogEntry`, with no database access of its own:
//! service resolution is delegated to a `ServiceResolver`, so the whole
//! pipeline is testable with in-memory fakes.
//!
//! The `Scanner` owns the batching/flushing; everything that happens to a
//! single line happens here.

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use tracing::warn;
use uuid::Uuid;

use crate::db::models::{InsertLogEntry, InsertService};
use crate::db::repositories::service_repo::ServiceRepository;
use crate::error::SentinelError;
use crate::log_scanner::classifier::{Classifier, ThreatLevel, ThreatResult};
use crate::log_scanner::filter::{FilterResult, NoiseFilter};
use crate::log_scanner::parser::auth::AuthLogParser;
use crate::log_scanner::parser::nginx::NginxAccessParser;
use crate::log_scanner::parser::{LogLevel, LogParser};
use crate::log_scanner::source::vhost_from_file_path;
use crate::log_scanner::tailer::TailLine;

/// A boxed, send, lifetime-bound future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// `unit_type` stored for services derived from nginx vhost access logs.
pub const UNIT_TYPE_NGINX_VHOST: &str = "nginx-vhost";
/// `unit_type` stored for services derived from plain log files.
pub const UNIT_TYPE_SYSTEM_LOG: &str = "system-log";

/// Resolves a service name to a stable database ID.
///
/// Production wires this to `ServiceRepository` (with caching); tests use
/// [`InMemoryServiceResolver`].
pub trait ServiceResolver: Send + Sync {
    /// Return the id for `name`, creating it on first use. Returns `None`
    /// if the service could not be resolved (the entry is then stored
    /// without a service link).
    fn resolve(
        &self,
        name: &str,
        unit_type: &str,
        virtual_host: Option<&str>,
    ) -> BoxFuture<'_, Option<Uuid>>;
}

/// [`ServiceResolver`] backed by the `services` table.
///
/// Resolved ids are cached in memory so that a burst of lines for the
/// same service causes at most one `get_or_create` round-trip instead of
/// one per line.
#[derive(Clone)]
pub struct DbServiceResolver {
    repo: ServiceRepository,
    cache: Arc<Mutex<HashMap<String, Uuid>>>,
}

impl DbServiceResolver {
    #[must_use]
    pub fn new(repo: ServiceRepository) -> Self {
        Self {
            repo,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl ServiceResolver for DbServiceResolver {
    fn resolve(
        &self,
        name: &str,
        unit_type: &str,
        virtual_host: Option<&str>,
    ) -> BoxFuture<'_, Option<Uuid>> {
        let name = name.to_string();
        let unit_type = unit_type.to_string();
        let virtual_host = virtual_host.map(str::to_string);
        let cache = self.cache.clone();
        let repo = self.repo.clone();

        Box::pin(async move {
            if let Some(&id) = cache.lock().unwrap().get(&name) {
                return Some(id);
            }

            let service = InsertService {
                name: name.clone(),
                unit_type,
                log_paths: None,
                virtual_host,
            };
            match repo.get_or_create(&service).await {
                Ok(id) => {
                    cache.lock().unwrap().insert(name, id);
                    Some(id)
                }
                // The entry is still stored, just without a service link.
                Err(e) => {
                    warn!("failed to get/create service '{name}': {e}");
                    None
                }
            }
        })
    }
}

/// A `ServiceResolver` that assigns ids in memory — for tests and for
/// tooling that must not touch the database.
#[derive(Debug, Default)]
pub struct InMemoryServiceResolver {
    services: Arc<Mutex<HashMap<String, Uuid>>>,
}

impl InMemoryServiceResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The id assigned to `name`, if any.
    #[must_use]
    pub fn id_of(&self, name: &str) -> Option<Uuid> {
        self.services.lock().unwrap().get(name).copied()
    }
}

impl ServiceResolver for InMemoryServiceResolver {
    fn resolve(
        &self,
        name: &str,
        _unit_type: &str,
        _virtual_host: Option<&str>,
    ) -> BoxFuture<'_, Option<Uuid>> {
        let name = name.to_string();
        let services = self.services.clone();
        Box::pin(async move {
            let mut services = services.lock().unwrap();
            let id = *services.entry(name).or_insert_with(Uuid::new_v4);
            Some(id)
        })
    }
}

/// Selects the `LogParser` for a log file path.
///
/// Entries are tried in order; the last entry is the fallback and is
/// expected to be a catch-all (`names: vec!["*"]`).
#[derive(Default)]
pub struct ParserRegistry {
    matches: Vec<ParserMatch>,
}

struct ParserMatch {
    /// File names this parser handles; `"*"` matches everything.
    names: Vec<&'static str>,
    parser: Box<dyn LogParser>,
}

impl ParserMatch {
    fn matches(&self, file_name: &str) -> bool {
        self.names.iter().any(|n| *n == "*" || *n == file_name)
    }
}

impl ParserRegistry {
    /// The historical default mapping: `auth.log` gets the syslog parser,
    /// every other file gets the nginx access-log parser.
    #[must_use]
    pub fn default_registry() -> Self {
        Self {
            matches: vec![
                ParserMatch {
                    names: vec!["auth.log"],
                    parser: Box::new(AuthLogParser::new()),
                },
                ParserMatch {
                    names: vec!["*"],
                    parser: Box::new(NginxAccessParser::new()),
                },
            ],
        }
    }

    /// The parser that should handle the file at `file_path`.
    #[must_use]
    pub fn for_path(&self, file_path: &Path) -> &dyn LogParser {
        let file_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        self.matches
            .iter()
            .find(|m| m.matches(file_name))
            .or_else(|| self.matches.last())
            .map(|m| &*m.parser)
            .expect("parser registry must have at least one entry")
    }
}

/// Production pipeline wiring: the default parser registry, a noise
/// filter built from `noise`, and DB-backed service resolution with
/// caching.
#[must_use]
pub fn build_pipeline(
    pool: sqlx::PgPool,
    noise: &crate::config::NoiseFilterConfig,
) -> Arc<Pipeline> {
    Arc::new(Pipeline::new(
        ParserRegistry::default_registry(),
        Arc::new(NoiseFilter::from_config(noise)),
        Arc::new(Classifier::new()),
        Arc::new(DbServiceResolver::new(ServiceRepository::new(pool))),
    ))
}

/// Turns `TailLine`s into `InsertLogEntry` records.
pub struct Pipeline {
    parsers: ParserRegistry,
    filter: Arc<NoiseFilter>,
    classifier: Arc<Classifier>,
    services: Arc<dyn ServiceResolver>,
}

impl Pipeline {
    #[must_use]
    pub fn new(
        parsers: ParserRegistry,
        filter: Arc<NoiseFilter>,
        classifier: Arc<Classifier>,
        services: Arc<dyn ServiceResolver>,
    ) -> Self {
        Self {
            parsers,
            filter,
            classifier,
            services,
        }
    }

    /// Process one line through parse → filter → classify → insert model.
    ///
    /// Returns `Ok(None)` for lines that carry no data (empty lines, or
    /// lines a parser explicitly declines).
    #[must_use]
    // `status_code` is 3 digits and `response_time_ms` is non-negative, so
    // the signed casts below cannot wrap in practice.
    #[allow(clippy::cast_possible_wrap)]
    pub fn process_line<'l>(
        &'l self,
        line: &'l TailLine,
    ) -> BoxFuture<'l, Result<Option<InsertLogEntry>, SentinelError>> {
        Box::pin(async move {
            let parser = self.parsers.for_path(&line.file_path);
            let parsed = parser.parse(&line.line).map_err(|e| {
                SentinelError::ParseError(format!(
                    "{} [{}]: {e}",
                    parser.name(),
                    line.file_path.display()
                ))
            })?;

            let Some(entry) = parsed else {
                return Ok(None);
            };

            let filter_result = self.filter.evaluate(&entry);
            let threat = self.classifier.classify(&entry);

            // Exclude and Aggregate are both stored as noise (raw line
            // suppressed); FlagSecurity is stored as a security event.
            let is_noise = matches!(
                filter_result,
                FilterResult::Exclude(_) | FilterResult::Aggregate(_)
            );
            let noise_reason = match &filter_result {
                FilterResult::Exclude(reason) | FilterResult::Aggregate(reason) => {
                    Some(reason.clone())
                }
                _ => None,
            };

            let virtual_host = vhost_from_file_path(&line.file_path)
                .or_else(|| entry.metadata.virtual_host.clone());

            let service_id = if let Some(vhost) = &virtual_host {
                self.services
                    .resolve(vhost.as_str(), UNIT_TYPE_NGINX_VHOST, Some(vhost.as_str()))
                    .await
            } else {
                let file_name = line
                    .file_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown-log")
                    .to_string();
                self.services
                    .resolve(&file_name, UNIT_TYPE_SYSTEM_LOG, None)
                    .await
            };

            let mut level = Self::classify_level(entry.level, &threat);
            if filter_result.is_security_flag() {
                level = LogLevel::Security;
            }

            Ok(Some(InsertLogEntry {
                service_id,
                timestamp: entry.timestamp,
                level: level.as_str().to_string(),
                message: entry.message,
                raw_line: if is_noise { None } else { Some(entry.raw) },
                client_ip: entry.metadata.client_ip.map(|ip| ip.to_string()),
                request_path: entry.metadata.request_path,
                status_code: entry.metadata.status_code.map(|s| s as i16),
                response_time_ms: entry.metadata.response_time_ms.map(|ms| ms as i64),
                is_noise,
                noise_reason,
                threat_level: threat.threat_level.as_str().to_string(),
                threat_categories: threat
                    .categories
                    .iter()
                    .map(|c| c.as_str().to_string())
                    .collect(),
            }))
        })
    }

    /// Map a parser level plus threat result to the stored level.
    /// High/Critical threats are stored as `security` regardless of the
    /// base level.
    #[must_use]
    pub fn classify_level(base_level: LogLevel, threat: &ThreatResult) -> LogLevel {
        if threat.threat_level >= ThreatLevel::High {
            LogLevel::Security
        } else {
            base_level
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_scanner::filter::NoiseFilter;
    use crate::log_scanner::tailer::TailLine;
    use std::path::PathBuf;

    fn pipeline() -> Pipeline {
        Pipeline::new(
            ParserRegistry::default_registry(),
            Arc::new(NoiseFilter::new()),
            Arc::new(Classifier::new()),
            Arc::new(InMemoryServiceResolver::new()),
        )
    }

    fn tail_line(file_name: &str, line: &str) -> TailLine {
        TailLine {
            file_path: PathBuf::from("/var/log/nginx").join(file_name),
            line: line.to_string(),
            byte_offset: 0,
        }
    }

    #[tokio::test]
    async fn test_nginx_line_produces_insert_entry() {
        let p = pipeline();
        let line = tail_line(
            "api.example.com-access.log",
            "192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] \"GET /api/health HTTP/1.1\" 200 15 \"-\" \"curl/8.0\" \"api.example.com\" 0.123",
        );

        let entry = p.process_line(&line).await.unwrap().unwrap();

        assert_eq!(entry.level, "info");
        assert_eq!(entry.request_path, Some("/api/health".to_string()));
        assert_eq!(entry.status_code, Some(200));
        assert_eq!(entry.client_ip, Some("192.168.1.1".to_string()));
        assert!(!entry.is_noise);
        assert!(entry.raw_line.is_some());
        assert!(entry.service_id.is_some());
        assert_eq!(entry.threat_level, "none");
        assert!(entry.threat_categories.is_empty());
    }

    #[tokio::test]
    async fn test_vhost_derived_from_file_path() {
        let services = Arc::new(InMemoryServiceResolver::new());
        let p = Pipeline::new(
            ParserRegistry::default_registry(),
            Arc::new(NoiseFilter::new()),
            Arc::new(Classifier::new()),
            services.clone(),
        );
        let line = tail_line(
            "shop.example.com-access.log",
            "192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 15 \"-\" \"curl/8.0\" \"other.example.com\" 0.1",
        );

        let entry = p.process_line(&line).await.unwrap().unwrap();

        // File-path vhost wins over the $host field.
        assert_eq!(services.id_of("shop.example.com"), entry.service_id);
    }

    #[tokio::test]
    async fn test_auth_log_line_parsed_as_syslog() {
        let p = pipeline();
        let line = tail_line(
            "auth.log",
            "Jan 15 10:30:45 myhost sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2",
        );

        let entry = p.process_line(&line).await.unwrap().unwrap();

        assert_eq!(entry.level, "security");
        assert_eq!(entry.client_ip, Some("192.168.1.100".to_string()));
        assert_eq!(entry.threat_level, "medium");
        assert_eq!(entry.threat_categories, vec!["brute-force"]);
    }

    /// A health check from a non-excluded IP is noise: stored without a
    /// raw line, with the filter's reason.
    #[tokio::test]
    async fn test_health_check_from_non_excluded_ip_is_noise() {
        let p = pipeline();
        let line = tail_line(
            "app.example.com-access.log",
            "203.0.113.7 - - [01/Jan/2025:00:00:00 +0000] \"GET /health HTTP/1.1\" 200 15 \"-\" \"HealthChecker/1.0\" \"app.example.com\" 0.001",
        );

        let entry = p.process_line(&line).await.unwrap().unwrap();

        assert!(entry.is_noise);
        assert!(entry.raw_line.is_none());
        assert_eq!(entry.noise_reason.as_deref(), Some("health check"));
    }

    /// Static assets are noise regardless of client.
    #[tokio::test]
    async fn test_static_asset_is_noise() {
        let p = pipeline();
        let line = tail_line(
            "app.example.com-access.log",
            "203.0.113.8 - - [01/Jan/2025:00:00:00 +0000] \"GET /styles/main.css HTTP/1.1\" 200 1500 \"-\" \"Mozilla/5.0\" \"app.example.com\" 0.02",
        );

        let entry = p.process_line(&line).await.unwrap().unwrap();

        assert!(entry.is_noise);
        assert!(entry.raw_line.is_none());
        assert_eq!(entry.noise_reason.as_deref(), Some("static asset"));
    }

    /// Known bot user agents are noise.
    #[tokio::test]
    async fn test_bot_user_agent_is_noise() {
        let p = pipeline();
        let line = tail_line(
            "app.example.com-access.log",
            "66.249.65.1 - - [01/Jan/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 15 \"-\" \"Mozilla/5.0 (compatible; Googlebot/2.1)\" \"app.example.com\" 0.1",
        );

        let entry = p.process_line(&line).await.unwrap().unwrap();

        assert!(entry.is_noise);
        assert!(entry.raw_line.is_none());
        assert!(
            entry
                .noise_reason
                .as_deref()
                .is_some_and(|r| r.starts_with("bot:"))
        );
    }

    /// Reconnaissance against a known scanner endpoint is stored as a
    /// security event even without a classified threat.
    #[tokio::test]
    async fn test_scanner_path_is_stored_as_security() {
        let p = pipeline();
        let line = tail_line(
            "app.example.com-access.log",
            "203.0.113.9 - - [01/Jan/2025:00:00:00 +0000] \"GET /wp-admin HTTP/1.1\" 404 0 \"-\" \"curl/8.0\" \"app.example.com\" 0.01",
        );

        let entry = p.process_line(&line).await.unwrap().unwrap();

        assert_eq!(entry.level, "security");
    }

    #[tokio::test]
    async fn test_excluded_ip_is_noise_without_raw_line() {
        let p = pipeline();
        // 127.0.0.1 is in the default excluded IP list.
        let line = tail_line(
            "app.example.com-access.log",
            "127.0.0.1 - - [01/Jan/2025:00:00:00 +0000] \"GET /health HTTP/1.1\" 200 15 \"-\" \"HealthChecker/1.0\" \"app.example.com\" 0.001",
        );

        let entry = p.process_line(&line).await.unwrap().unwrap();

        assert!(entry.is_noise);
        assert!(entry.raw_line.is_none());
        assert!(entry.noise_reason.is_some());
    }

    #[tokio::test]
    async fn test_attack_line_upgraded_to_security_level() {
        let p = pipeline();
        let line = tail_line(
            "app.example.com-access.log",
            "10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] \"GET /users?id=1 UNION SELECT * FROM passwords HTTP/1.1\" 400 0 \"-\" \"curl/8.0\" \"app.example.com\" 0.01",
        );

        let entry = p.process_line(&line).await.unwrap().unwrap();

        assert_eq!(entry.level, "security");
        assert_eq!(entry.threat_level, "high");
        assert_eq!(entry.threat_categories, vec!["sql-injection"]);
    }

    #[tokio::test]
    async fn test_unparseable_line_is_parse_error() {
        let p = pipeline();
        let line = tail_line("app.example.com-access.log", "completely bogus line");
        let result = p.process_line(&line).await;
        assert!(matches!(result, Err(SentinelError::ParseError(_))));
    }

    #[tokio::test]
    async fn test_empty_line_is_none() {
        let p = pipeline();
        let line = tail_line("app.example.com-access.log", "");
        let result = p.process_line(&line).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_service_resolver_caches_ids() {
        let services = Arc::new(InMemoryServiceResolver::new());
        let first = services
            .resolve("svc", UNIT_TYPE_NGINX_VHOST, Some("svc"))
            .await;
        let second = services
            .resolve("svc", UNIT_TYPE_NGINX_VHOST, Some("svc"))
            .await;
        assert_eq!(first, second);
        assert_eq!(first, services.id_of("svc"));
    }

    /// `build_pipeline` must produce a working pipeline even when the
    /// database is unreachable: the entry is still stored, just without a
    /// service link.
    #[tokio::test]
    async fn test_build_pipeline_works_without_live_db() {
        let pool = sqlx::PgPool::connect_lazy("postgresql://invalid:5432/none")
            .expect("lazy pool does not connect");
        let p = build_pipeline(pool, &crate::config::NoiseFilterConfig::default());
        let line = tail_line(
            "app.example.com-access.log",
            "10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 15 \"-\" \"curl/8.0\" \"app.example.com\" 0.1",
        );

        let entry = p.process_line(&line).await.unwrap().unwrap();
        assert_eq!(entry.level, "info");
        assert!(entry.service_id.is_none(), "no service link without a DB");
    }

    #[test]
    fn test_parser_registry_selects_auth_parser() {
        let registry = ParserRegistry::default_registry();
        let parser = registry.for_path(Path::new("/var/log/auth.log"));
        assert_eq!(parser.name(), "syslog");
    }

    #[test]
    fn test_parser_registry_defaults_to_nginx_parser() {
        let registry = ParserRegistry::default_registry();
        let parser = registry.for_path(Path::new("/var/log/nginx/access.log"));
        assert_eq!(parser.name(), "nginx_combined");
    }

    #[test]
    fn test_classify_level_security_threat() {
        let threat = ThreatResult {
            threat_level: ThreatLevel::High,
            categories: vec![],
            confidence: 0.9,
        };
        assert_eq!(
            Pipeline::classify_level(LogLevel::Info, &threat),
            LogLevel::Security
        );
    }

    #[test]
    fn test_classify_level_base_levels() {
        let threat = ThreatResult {
            threat_level: ThreatLevel::None,
            categories: vec![],
            confidence: 0.0,
        };
        assert_eq!(
            Pipeline::classify_level(LogLevel::Info, &threat),
            LogLevel::Info
        );
        assert_eq!(
            Pipeline::classify_level(LogLevel::Error, &threat),
            LogLevel::Error
        );
        assert_eq!(
            Pipeline::classify_level(LogLevel::Security, &threat),
            LogLevel::Security
        );
    }

    /// `as_str` → `from_db` must round-trip for every level, and unknown
    /// stored values must fall back to `Info`.
    #[test]
    fn test_log_level_db_roundtrip() {
        for level in [
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warn,
            LogLevel::Error,
            LogLevel::Critical,
            LogLevel::Security,
        ] {
            assert_eq!(LogLevel::from_db(level.as_str()), level);
        }
        assert_eq!(LogLevel::from_db("bogus"), LogLevel::Info);
        assert_eq!(LogLevel::from_db(""), LogLevel::Info);
    }
}
