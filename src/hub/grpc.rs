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
use crate::hub::pb::{Ack, LogLine, LogsRequest, MetricPoint, MetricsRequest};
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
fn validate_log_line(line: &LogLine) -> Result<InsertLogEntry, String> {
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

        let lines = request.into_inner().lines;
        if lines.len() > validate::MAX_LINES_PER_REQUEST {
            return Err(Status::invalid_argument(format!(
                "batch exceeds {} lines",
                validate::MAX_LINES_PER_REQUEST
            )));
        }

        // Resolve (and create) one service per container name — mirroring
        // how the local daemon resolves vhost/filename sources.
        let mut service_cache: std::collections::HashMap<String, Option<uuid::Uuid>> =
            std::collections::HashMap::new();
        let mut entries = Vec::with_capacity(lines.len());
        let mut rejected: usize = 0;

        for line in &lines {
            match validate_log_line(line) {
                Ok(mut entry) => {
                    let service_id = if let Some(cached) = service_cache.get(&line.container) {
                        *cached
                    } else {
                        let resolved = self
                            .services
                            .get_or_create(&InsertService {
                                name: line.container.clone(),
                                unit_type: "docker-container".into(),
                                log_paths: None,
                                virtual_host: None,
                            })
                            .await
                            .ok();
                        service_cache.insert(line.container.clone(), resolved);
                        resolved
                    };
                    entry.service_id = service_id;
                    entries.push(entry);
                }
                Err(reason) => {
                    rejected += 1;
                    tracing::debug!(reason, "rejected log line from {hostname}");
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
