//! Daemon-parity host-log forwarding: tail → parse → filter → classify
//! locally, then ship structured entries to the hub over gRPC.
//!
//! This reuses the exact `log_scanner` pipeline the daemon runs; the only
//! swap is the sink: [`GrpcSink`] sends `ParsedLogEntry` protos instead
//! of writing to Postgres. Because the agent has no database, service
//! identity is resolved locally to names by [`AgentServiceResolver`] and
//! carried on the wire (`service_name`/`service_unit_type`); the hub owns
//! the `services` rows.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::config::Config;
use crate::db::models::InsertLogEntry;
use crate::error::SentinelError;
use crate::hub::pb::LogsRequest;
use crate::hub::pb::ParsedLogEntry as ProtoParsedLogEntry;
use crate::hub::validate;
use crate::log_scanner::classifier::Classifier;
use crate::log_scanner::filter::NoiseFilter;
use crate::log_scanner::pipeline::{BoxFuture, ParserRegistry, Pipeline, ServiceResolver};
use crate::log_scanner::scanner::{LogSink, Scanner};
use crate::log_scanner::tailer::FileTailer;

use super::HubClient;

/// Everything the hub needs to `get_or_create` a services row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceMeta {
    pub name: String,
    pub unit_type: String,
    pub virtual_host: Option<String>,
}

/// A [`ServiceResolver`] that assigns local uuids (like the in-memory
/// test resolver) and records the `name`/`unit_type`/`vhost` behind each
/// id so the gRPC sink can put the identity on the wire.
#[derive(Debug, Default)]
pub struct AgentServiceResolver {
    by_name: Arc<Mutex<HashMap<String, Uuid>>>,
    by_id: Arc<Mutex<HashMap<Uuid, ServiceMeta>>>,
}

impl AgentServiceResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The recorded identity for a local service id, if any.
    #[must_use]
    pub fn meta_of(&self, id: Uuid) -> Option<ServiceMeta> {
        self.by_id.lock().unwrap().get(&id).cloned()
    }
}

impl ServiceResolver for AgentServiceResolver {
    fn resolve(
        &self,
        name: &str,
        unit_type: &str,
        virtual_host: Option<&str>,
    ) -> BoxFuture<'_, Option<Uuid>> {
        let name = name.to_string();
        let unit_type = unit_type.to_string();
        let virtual_host = virtual_host.map(str::to_string);
        let by_name = self.by_name.clone();
        let by_id = self.by_id.clone();
        Box::pin(async move {
            let mut names = by_name.lock().unwrap();
            let id = *names.entry(name.clone()).or_insert_with(Uuid::new_v4);
            by_id.lock().unwrap().insert(
                id,
                ServiceMeta {
                    name,
                    unit_type,
                    virtual_host,
                },
            );
            Some(id)
        })
    }
}

/// Converts one pipeline entry into the wire message, looking the
/// service identity up in `resolver`.
#[must_use]
pub fn entry_to_proto(
    entry: &InsertLogEntry,
    resolver: &AgentServiceResolver,
) -> ProtoParsedLogEntry {
    let meta = entry.service_id.and_then(|id| resolver.meta_of(id));
    ProtoParsedLogEntry {
        timestamp_ms: entry.timestamp.timestamp_millis(),
        level: entry.level.clone(),
        message: entry.message.clone(),
        raw_line: entry.raw_line.clone(),
        client_ip: entry.client_ip.clone(),
        request_path: entry.request_path.clone(),
        status_code: entry.status_code.map(i32::from),
        response_time_ms: entry.response_time_ms,
        is_noise: entry.is_noise,
        noise_reason: entry.noise_reason.clone(),
        threat_level: entry.threat_level.clone(),
        threat_categories: entry.threat_categories.clone(),
        service_name: meta.as_ref().map_or_else(String::new, |m| m.name.clone()),
        service_unit_type: meta
            .as_ref()
            .map_or_else(String::new, |m| m.unit_type.clone()),
        virtual_host: meta.and_then(|m| m.virtual_host),
    }
}

/// [`LogSink`] that forwards batches to the hub as structured entries.
/// Send failures return `Err` so the [`Scanner`] re-queues and retries
/// the batch on the next flush tick.
pub struct GrpcSink {
    client: HubClient,
    resolver: Arc<AgentServiceResolver>,
}

impl GrpcSink {
    #[must_use]
    pub fn new(client: HubClient, resolver: Arc<AgentServiceResolver>) -> Self {
        Self { client, resolver }
    }
}

impl LogSink for GrpcSink {
    fn insert_batch<'s>(
        &'s self,
        entries: &'s [InsertLogEntry],
    ) -> BoxFuture<'s, Result<usize, SentinelError>> {
        Box::pin(async move {
            let parsed = entries
                .iter()
                .map(|e| entry_to_proto(e, &self.resolver))
                .collect();
            let request = LogsRequest {
                lines: vec![],
                parsed_lines: parsed,
            };
            self.client
                .send_logs_request(request)
                .await
                .map_err(|e| SentinelError::ServiceError(format!("log forward failed: {e}")))?;
            Ok(entries.len())
        })
    }
}

/// Builds the agent pipeline: same parsers/classifier as the daemon,
/// noise filter from config, and name-recording service resolution.
#[must_use]
pub fn build_agent_pipeline(config: &Config) -> (Arc<Pipeline>, Arc<AgentServiceResolver>) {
    let resolver = Arc::new(AgentServiceResolver::new());
    let pipeline = Arc::new(Pipeline::new(
        ParserRegistry::default_registry(),
        Arc::new(NoiseFilter::from_config(&config.noise_filter)),
        Arc::new(Classifier::new()),
        resolver.clone(),
    ));
    (pipeline, resolver)
}

/// Starts the tailer + scanner + gRPC sink in a background task sharing
/// the agent's `cancel` token. The final batch is flushed when the token
/// fires (the scanner's shutdown flush returns the error upstream — the
/// task logs it).
///
/// # Errors
/// Config error on an invalid watch pattern.
pub fn spawn_log_forwarding(
    config: &Config,
    client: &HubClient,
    cancel: &CancellationToken,
) -> Result<(), SentinelError> {
    let mut tailer = FileTailer::from_watch_config(&config.log_watching)?;
    let (pipeline, resolver) = build_agent_pipeline(config);
    // The hub rejects requests over this many lines; clamp the scanner
    // batch so a flush always fits in one request.
    let batch_size = config
        .agent
        .log_batch_size
        .clamp(1, validate::MAX_LINES_PER_REQUEST);
    let interval = std::time::Duration::from_secs(config.agent.log_flush_interval_secs.max(1));
    let scanner = Scanner::with_cancel(pipeline, batch_size, Some(interval), cancel.clone());
    let sink = GrpcSink::new(client.clone(), resolver);

    tokio::spawn(async move {
        match tailer.start().await {
            Ok(rx) => {
                if let Err(e) = scanner.run(rx, &sink).await {
                    tracing::error!("agent log forwarding stopped: {e}");
                }
            }
            Err(e) => tracing::error!("agent tailer failed to start: {e}"),
        }
    });
    tracing::info!("agent host-log forwarding started (daemon parity)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_scanner::pipeline::UNIT_TYPE_NGINX_VHOST;
    use chrono::{TimeZone, Utc};

    fn entry(service_id: Option<Uuid>) -> InsertLogEntry {
        InsertLogEntry {
            service_id,
            timestamp: Utc
                .timestamp_millis_opt(1_700_000_000_000)
                .single()
                .expect("valid ts"),
            level: "security".to_string(),
            message: "sqlmap hit".to_string(),
            raw_line: Some("raw line".to_string()),
            client_ip: Some("203.0.113.9".to_string()),
            request_path: Some("/users?id=1 UNION SELECT".to_string()),
            status_code: Some(400),
            response_time_ms: Some(12),
            is_noise: false,
            noise_reason: None,
            threat_level: "high".to_string(),
            threat_categories: vec!["sql-injection".to_string()],
            source_host: None,
        }
    }

    async fn resolve_vhost(resolver: &AgentServiceResolver) -> Uuid {
        resolver
            .resolve(
                "api.example.com",
                UNIT_TYPE_NGINX_VHOST,
                Some("api.example.com"),
            )
            .await
            .expect("agent resolver always resolves")
    }

    #[tokio::test]
    async fn test_entry_to_proto_preserves_all_structured_fields() {
        let resolver = AgentServiceResolver::new();
        let id = resolve_vhost(&resolver).await;
        let proto = entry_to_proto(&entry(Some(id)), &resolver);

        assert_eq!(proto.timestamp_ms, 1_700_000_000_000);
        assert_eq!(proto.level, "security");
        assert_eq!(proto.raw_line.as_deref(), Some("raw line"));
        assert_eq!(proto.client_ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(proto.status_code, Some(400));
        assert_eq!(proto.response_time_ms, Some(12));
        assert!(!proto.is_noise);
        assert_eq!(proto.threat_level, "high");
        assert_eq!(proto.threat_categories, vec!["sql-injection"]);
        assert_eq!(proto.service_name, "api.example.com");
        assert_eq!(proto.service_unit_type, UNIT_TYPE_NGINX_VHOST);
        assert_eq!(proto.virtual_host.as_deref(), Some("api.example.com"));
    }

    #[tokio::test]
    async fn test_entry_to_proto_without_service_sends_empty_identity() {
        let resolver = AgentServiceResolver::new();
        let proto = entry_to_proto(&entry(None), &resolver);
        assert!(proto.service_name.is_empty());
        assert!(proto.service_unit_type.is_empty());
        assert!(proto.virtual_host.is_none());
    }

    #[tokio::test]
    async fn test_noise_entry_roundtrips_noise_fields() {
        let resolver = AgentServiceResolver::new();
        let id = resolve_vhost(&resolver).await;
        let mut e = entry(Some(id));
        e.is_noise = true;
        e.noise_reason = Some("static asset".to_string());
        e.raw_line = None;
        let proto = entry_to_proto(&e, &resolver);
        assert!(proto.is_noise);
        assert_eq!(proto.noise_reason.as_deref(), Some("static asset"));
        assert!(proto.raw_line.is_none());
    }

    #[tokio::test]
    async fn test_resolver_is_stable_per_name() {
        let resolver = AgentServiceResolver::new();
        let first = resolve_vhost(&resolver).await;
        let second = resolve_vhost(&resolver).await;
        assert_eq!(first, second);
        assert_eq!(resolver.meta_of(first).unwrap().name, "api.example.com");
    }

    #[test]
    fn test_build_agent_pipeline_needs_no_database() {
        let config = Config::default();
        let (pipeline, _resolver) = build_agent_pipeline(&config);
        assert!(Arc::strong_count(&pipeline) >= 1);
    }
}
