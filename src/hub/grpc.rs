//! The gRPC ingestion service (`sentinel.v1.Ingest`).
//!
//! Authentication happens in-handler: metadata key + per-connection rate
//! budget are checked before any expensive work. The authenticated
//! [`Principal`] provides the trusted identity — handlers never read
//! identity from the message (there are no identity fields in the
//! protocol).

use chrono::{TimeZone, Utc};
use tonic::{Request, Response, Status};

use crate::db::models::InsertLogEntry;
use crate::db::models::InsertService;
use crate::db::repositories::agent_repo::AgentRepository;
use crate::db::repositories::api_key_repo::ApiKeyRepository;
use crate::db::repositories::log_entry_repo::LogEntryRepository;
use crate::db::repositories::service_repo::ServiceRepository;
use crate::db::repositories::system_metric_repo::{InsertSystemMetric, SystemMetricRepository};
use crate::hub::auth::{AuthError, AuthService, Permission, Principal};
use crate::hub::pb::ingest_server::Ingest;
use crate::hub::pb::{Ack, LogLine, LogsRequest, MetricPoint, MetricsRequest, ParsedLogEntry};
use crate::hub::validate;

/// The gRPC ingestion service. Cheap to clone; shares the auth cache.
#[derive(Clone)]
pub struct IngestService {
    auth: AuthService,
    agents: AgentRepository,
    metrics: SystemMetricRepository,
    logs: LogEntryRepository,
    services: ServiceRepository,
}

impl IngestService {
    /// Builds the service from the shared pool.
    #[must_use]
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            auth: AuthService::new(ApiKeyRepository::new(pool.clone())),
            agents: AgentRepository::new(pool.clone()),
            metrics: SystemMetricRepository::new(pool.clone()),
            logs: LogEntryRepository::new(pool.clone()),
            services: ServiceRepository::new(pool),
        }
    }

    /// Authenticates the request: extracts `x-api-key` metadata, applies
    /// the per-IP attempt budget, then verifies the key.
    // `tonic::Status` is the required error type of the handler trait.
    #[allow(unknown_lints, clippy::result_large_err)]
    async fn authorize(
        &self,
        request: &Request<impl std::fmt::Debug>,
    ) -> Result<Principal, Status> {
        let raw_key = request
            .metadata()
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("missing x-api-key metadata"))?;

        let ip = request
            .remote_addr()
            .map_or_else(|| "unknown".to_string(), |addr| addr.ip().to_string());
        if let Err(e) = self.auth.check_ip_budget(&ip) {
            return Err(auth_status(&e, &ip));
        }

        match self.auth.authenticate(raw_key).await {
            Ok(principal) => Ok(principal),
            Err(e) => Err(auth_status(&e, &ip)),
        }
    }
}

/// Maps an [`AuthError`] to a gRPC status, logging failures for the audit trail.
fn auth_status(error: &AuthError, ip: &str) -> Status {
    // Audit log for failures (success is not logged to avoid noise).
    if !matches!(error, AuthError::Storage(_)) {
        tracing::warn!(ip, "gRPC auth failure: {error}");
    }
    match error {
        AuthError::Malformed | AuthError::UnknownKey | AuthError::BadSignature => {
            Status::unauthenticated(error.to_string())
        }
        AuthError::RateLimited => Status::resource_exhausted(error.to_string()),
        AuthError::Storage(message) => {
            Status::internal(format!("authentication storage failure: {message}"))
        }
    }
}

/// Converts proto milliseconds to a UTC timestamp.
fn ts_from_ms(ms: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_millis_opt(ms)
        .single()
        .unwrap_or_else(Utc::now)
}

/// Validates a metric point; returns the DB-ready struct or a reject reason.
fn validate_point(point: &MetricPoint, hostname: &str) -> Result<InsertSystemMetric, String> {
    let timestamp = ts_from_ms(point.timestamp_ms);
    validate::timestamp(timestamp, Utc::now())?;

    let finite = |value: f64, name: &str| -> Result<f64, String> {
        if value.is_finite() && value >= 0.0 {
            Ok(value)
        } else {
            Err(format!("{name} must be a finite non-negative number"))
        }
    };

    Ok(InsertSystemMetric {
        host: Some(hostname.to_string()),
        timestamp,
        cpu_usage_percent: finite(point.cpu_percent, "cpu_percent")?,
        memory_used_bytes: point.mem_used_bytes.min(i64::MAX as u64) as i64,
        memory_total_bytes: point.mem_total_bytes.min(i64::MAX as u64) as i64,
        disk_used_bytes: point.disk_used_bytes.min(i64::MAX as u64) as i64,
        disk_total_bytes: point.disk_total_bytes.min(i64::MAX as u64) as i64,
        load_avg_1m: finite(point.load_1m, "load_1m")?,
        load_avg_5m: finite(point.load_5m, "load_5m")?,
        network_rx_bytes: point.net_rx_bytes_total.min(i64::MAX as u64) as i64,
        network_tx_bytes: point.net_tx_bytes_total.min(i64::MAX as u64) as i64,
    })
}

/// Converts a proto log line to a DB-ready entry; `Err` for invalid lines
/// (counted and reported, never silently dropped).
fn validate_log_line(line: &LogLine, hostname: &str) -> Result<InsertLogEntry, String> {
    validate::container(&line.container)?;
    validate::stream(&line.stream)?;
    let timestamp = ts_from_ms(line.timestamp_ms);
    validate::timestamp(timestamp, Utc::now())?;
    let message = validate::sanitize_message(&line.message);

    // stderr lines carry an error level; stdout is info.
    let level = if line.stream == "stderr" {
        "error"
    } else {
        "info"
    };

    Ok(InsertLogEntry {
        service_id: None, // resolved below by container name
        timestamp,
        level: level.into(),
        message: message.clone(),
        raw_line: Some(message),
        client_ip: None,
        request_path: None,
        status_code: None,
        response_time_ms: None,
        is_noise: false,
        noise_reason: None,
        threat_level: "none".into(),
        threat_categories: vec![],
        source_host: Some(hostname.into()),
    })
}

/// A parsed entry ready for storage, plus the service identity the agent
/// resolved locally (the hub owns the `services` rows).
struct ParsedIngest {
    entry: InsertLogEntry,
    service_name: String,
    service_unit_type: String,
    virtual_host: Option<String>,
}

/// Converts an agent-parsed entry to a DB-ready record. The entry is
/// already classified by the agent's pipeline: the hub validates shapes
/// and bounds only, never re-parses or re-classifies (AGENTS.md).
fn validate_parsed_entry(parsed: &ParsedLogEntry, hostname: &str) -> Result<ParsedIngest, String> {
    let timestamp = ts_from_ms(parsed.timestamp_ms);
    validate::timestamp(timestamp, Utc::now())?;
    validate::level(&parsed.level)?;
    validate::threat_level(&parsed.threat_level)?;
    validate::threat_categories(&parsed.threat_categories)?;
    let message = validate::sanitize_message(&parsed.message);
    let raw_line = parsed.raw_line.as_deref().map(validate::sanitize_message);
    if let Some(ip) = &parsed.client_ip {
        validate::client_ip(ip)?;
    }
    if let Some(path) = &parsed.request_path {
        validate::request_path(path)?;
    }
    if let Some(reason) = &parsed.noise_reason {
        validate::short_text(reason, "noise_reason")?;
    }
    let status_code = parsed.status_code.unwrap_or(0);
    if !(0..=599).contains(&status_code) {
        return Err(format!("status_code {status_code} out of range"));
    }
    if parsed.response_time_ms.is_some_and(|ms| ms < 0) {
        return Err("response_time_ms must be non-negative".to_string());
    }
    if parsed.service_name.is_empty() || parsed.service_unit_type.is_empty() {
        return Err("parsed entries must carry a service identity".to_string());
    }
    validate::service_name(&parsed.service_name)?;
    validate::unit_type(&parsed.service_unit_type)?;
    if let Some(vhost) = &parsed.virtual_host {
        validate::service_name(vhost)?;
    }

    Ok(ParsedIngest {
        entry: InsertLogEntry {
            service_id: None, // resolved below by service name
            timestamp,
            level: parsed.level.clone(),
            message,
            raw_line,
            client_ip: parsed.client_ip.clone(),
            request_path: parsed.request_path.clone(),
            status_code: if status_code == 0 {
                None // proto3 sentinel: 0 means "unset"
            } else {
                i16::try_from(status_code).ok()
            },
            response_time_ms: parsed.response_time_ms,
            is_noise: parsed.is_noise,
            noise_reason: parsed.noise_reason.clone(),
            threat_level: parsed.threat_level.clone(),
            threat_categories: parsed.threat_categories.clone(),
            source_host: Some(hostname.into()),
        },
        service_name: parsed.service_name.clone(),
        service_unit_type: parsed.service_unit_type.clone(),
        virtual_host: parsed.virtual_host.clone(),
    })
}

#[tonic::async_trait]
impl Ingest for IngestService {
    async fn send_metrics(
        &self,
        request: Request<MetricsRequest>,
    ) -> Result<Response<Ack>, Status> {
        let principal = self.authorize(&request).await?;

        if !principal.permissions.contains(&Permission::IngestMetrics) {
            return Err(Status::permission_denied("key lacks ingest:metrics"));
        }
        let (Some(agent_id), Some(hostname)) = (&principal.agent_id, &principal.hostname) else {
            return Err(Status::permission_denied(
                "this key is not bound to an agent; agent keys are required for ingestion",
            ));
        };

        let point = request
            .into_inner()
            .point
            .ok_or_else(|| Status::invalid_argument("missing metric point"))?;
        let metric = validate_point(&point, hostname).map_err(Status::invalid_argument)?;

        self.agents
            .upsert_seen(agent_id, hostname)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        self.metrics
            .insert(&metric)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(Ack {
            accepted: true,
            count: 1,
        }))
    }

    async fn send_logs(&self, request: Request<LogsRequest>) -> Result<Response<Ack>, Status> {
        let principal = self.authorize(&request).await?;

        if !principal.permissions.contains(&Permission::IngestLogs) {
            return Err(Status::permission_denied("key lacks ingest:logs"));
        }
        let (Some(_agent_id), Some(hostname)) = (&principal.agent_id, &principal.hostname) else {
            return Err(Status::permission_denied(
                "this key is not bound to an agent; agent keys are required for ingestion",
            ));
        };

        let req = request.into_inner();
        let total = req.lines.len() + req.parsed_lines.len();
        if total > validate::MAX_LINES_PER_REQUEST {
            return Err(Status::invalid_argument(format!(
                "batch exceeds {} lines",
                validate::MAX_LINES_PER_REQUEST
            )));
        }

        // Resolve (and create) one service row per source — containers for
        // raw Docker lines, and the agent-side vhost/filename identity for
        // parsed entries. Both mirror how the local daemon resolves
        // sources; the agent has no database, so IDs stay hub-local.
        let mut service_cache: std::collections::HashMap<(String, String), Option<uuid::Uuid>> =
            std::collections::HashMap::new();
        let mut entries = Vec::with_capacity(total);
        let mut rejected: usize = 0;

        for line in &req.lines {
            match validate_log_line(line, hostname) {
                Ok(mut entry) => {
                    let key = ("docker-container".to_string(), line.container.clone());
                    let resolved = if let Some(&cached) = service_cache.get(&key) {
                        cached
                    } else {
                        let created = self
                            .services
                            .get_or_create(&InsertService {
                                name: key.1.clone(),
                                unit_type: key.0.clone(),
                                log_paths: None,
                                virtual_host: None,
                            })
                            .await
                            .ok();
                        service_cache.insert(key, created);
                        created
                    };
                    entry.service_id = resolved;
                    entries.push(entry);
                }
                Err(reason) => {
                    rejected += 1;
                    tracing::debug!(reason, "rejected log line from {hostname}");
                }
            }
        }

        for parsed in &req.parsed_lines {
            match validate_parsed_entry(parsed, hostname) {
                Ok(mut ingest) => {
                    let key = (
                        ingest.service_unit_type.clone(),
                        ingest.service_name.clone(),
                    );
                    let resolved = if let Some(&cached) = service_cache.get(&key) {
                        cached
                    } else {
                        let created = self
                            .services
                            .get_or_create(&InsertService {
                                name: key.1.clone(),
                                unit_type: key.0.clone(),
                                log_paths: None,
                                virtual_host: ingest.virtual_host.clone(),
                            })
                            .await
                            .ok();
                        service_cache.insert(key, created);
                        created
                    };
                    ingest.entry.service_id = resolved;
                    entries.push(ingest.entry);
                }
                Err(reason) => {
                    rejected += 1;
                    tracing::debug!(reason, "rejected parsed entry from {hostname}");
                }
            }
        }

        if !entries.is_empty() {
            self.logs
                .insert_batch(&entries)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
        }

        tracing::debug!(
            hostname,
            accepted = entries.len(),
            rejected,
            "logs ingested"
        );
        Ok(Response::new(Ack {
            accepted: true,
            count: u32::try_from(entries.len()).unwrap_or(u32::MAX),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed_entry() -> ParsedLogEntry {
        ParsedLogEntry {
            timestamp_ms: Utc::now().timestamp_millis(),
            level: "security".into(),
            message: "GET /users?id=1 UNION SELECT".into(),
            raw_line: Some("192.0.2.1 - - [...] \"GET ...\"".into()),
            client_ip: Some("203.0.113.9".into()),
            request_path: Some("/users?id=1 UNION SELECT".into()),
            status_code: Some(400),
            response_time_ms: Some(12),
            is_noise: false,
            noise_reason: None,
            threat_level: "high".into(),
            threat_categories: vec!["sql-injection".into()],
            service_name: "api.example.com".into(),
            service_unit_type: "nginx-vhost".into(),
            virtual_host: Some("api.example.com".into()),
        }
    }

    #[test]
    fn test_validate_parsed_entry_maps_all_fields() {
        let ingest = validate_parsed_entry(&parsed_entry(), "vps1").unwrap();
        let e = &ingest.entry;
        assert_eq!(e.level, "security");
        assert_eq!(e.threat_level, "high");
        assert_eq!(e.threat_categories, vec!["sql-injection"]);
        assert_eq!(e.status_code, Some(400));
        assert_eq!(e.response_time_ms, Some(12));
        assert_eq!(e.client_ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(e.source_host.as_deref(), Some("vps1"));
        assert!(e.raw_line.is_some());
        assert_eq!(ingest.service_name, "api.example.com");
        assert_eq!(ingest.service_unit_type, "nginx-vhost");
        assert_eq!(ingest.virtual_host.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn test_validate_parsed_entry_rejects_bad_vocabularies() {
        let mut e = parsed_entry();
        e.level = "apocalyptic".into();
        assert!(validate_parsed_entry(&e, "h").is_err());

        let mut e = parsed_entry();
        e.threat_level = "catastrophic".into();
        assert!(validate_parsed_entry(&e, "h").is_err());

        let mut e = parsed_entry();
        e.client_ip = Some("not-an-ip".into());
        assert!(validate_parsed_entry(&e, "h").is_err());
    }

    #[test]
    fn test_validate_parsed_entry_rejects_bad_service_identity() {
        let mut e = parsed_entry();
        e.service_name = String::new();
        assert!(validate_parsed_entry(&e, "h").is_err());

        let mut e = parsed_entry();
        e.service_name = "../etc/passwd".into();
        assert!(validate_parsed_entry(&e, "h").is_err());

        let mut e = parsed_entry();
        e.service_unit_type = "NGINX VHOST".into();
        assert!(validate_parsed_entry(&e, "h").is_err());
    }

    #[test]
    fn test_validate_parsed_entry_rejects_far_future_timestamp() {
        let mut e = parsed_entry();
        e.timestamp_ms = (Utc::now() + chrono::Duration::hours(2)).timestamp_millis();
        assert!(validate_parsed_entry(&e, "h").is_err());
    }

    #[test]
    fn test_validate_parsed_entry_rejects_out_of_range_status() {
        let mut e = parsed_entry();
        e.status_code = Some(999);
        assert!(validate_parsed_entry(&e, "h").is_err());
        let mut e = parsed_entry();
        e.status_code = Some(0);
        // 0 means "unset" and maps to None.
        let ingest = validate_parsed_entry(&e, "h").unwrap();
        assert_eq!(ingest.entry.status_code, None);
    }

    #[test]
    fn test_validate_log_line_sets_source_host() {
        let line = LogLine {
            timestamp_ms: Utc::now().timestamp_millis(),
            container: "app".into(),
            stream: "stdout".into(),
            message: "hello".into(),
        };
        let e = validate_log_line(&line, "vps2").unwrap();
        assert_eq!(e.source_host.as_deref(), Some("vps2"));
        assert_eq!(e.level, "info");
    }
}
