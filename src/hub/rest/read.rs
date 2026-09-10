//! Read endpoints for the dashboard SPA: metrics, events, servers, summary.

use std::sync::Arc;

use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::db::repositories::agent_repo::{AgentStatus, ONLINE_WINDOW_SECS};
use crate::db::repositories::app_event_repo::{AppEventRepository, AppEventRow, EventFilter};
use crate::db::repositories::system_metric_repo::{BucketedMetric, SystemMetricRepository};
use crate::hub::auth::Permission;
use crate::hub::range::MetricRange;
use crate::hub::rest::auth::PrincipalExtractor;
use crate::hub::validate;

/// Shared read-side state.
pub struct ReadState {
    metrics: SystemMetricRepository,
    events: AppEventRepository,
    agents: crate::db::repositories::agent_repo::AgentRepository,
}

impl ReadState {
    #[must_use]
    pub fn new(
        metrics: SystemMetricRepository,
        events: AppEventRepository,
        agents: crate::db::repositories::agent_repo::AgentRepository,
    ) -> Self {
        Self {
            metrics,
            events,
            agents,
        }
    }
}

/// `GET /api/v1/health` — the only public route.
///
/// # Errors
/// Never fails.
pub async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "status": "ok" }))
}

// ---- GET /api/v1/metrics ----

/// Rejects keys without the `read:dashboard` permission. Every read
/// handler must call this: authentication alone is not authorization.
fn require_dashboard(principal: &PrincipalExtractor) -> Option<HttpResponse> {
    if principal.0.permissions.contains(&Permission::ReadDashboard) {
        None
    } else {
        Some(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "key lacks read:dashboard"
        })))
    }
}

#[derive(Debug, Serialize)]
pub struct MetricPointDto {
    pub timestamp: String,
    pub cpu_percent: f64,
    pub mem_used_bytes: i64,
    pub mem_total_bytes: i64,
    pub load_1m: f64,
    pub load_5m: f64,
    pub disk_used_bytes: i64,
    pub disk_total_bytes: i64,
}

#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    pub metrics: Vec<MetricPointDto>,
}

/// `GET /api/v1/metrics?range=24h&host=...`
///
/// # Errors
/// 400 for an out-of-allowlist range; 500 on storage failure.
pub async fn get_metrics(
    state: web::Data<ReadState>,
    principal: crate::hub::rest::auth::PrincipalExtractor,
    query: web::Query<MetricsQuery>,
) -> HttpResponse {
    if let Some(denied) = require_dashboard(&principal) {
        return denied;
    }
    let Some(range) = MetricRange::parse(query.range.as_deref().unwrap_or("24h")) else {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "range must be one of 1h, 6h, 24h, 7d, 30d"
        }));
    };

    match state
        .metrics
        .bucketed_series(
            range.interval(),
            range.bucket_seconds(),
            range.max_rows(),
            query.host.as_deref(),
        )
        .await
    {
        Ok(series) => HttpResponse::Ok().json(MetricsResponse {
            metrics: series
                .into_iter()
                .map(|b: BucketedMetric| MetricPointDto {
                    timestamp: b.bucket.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    cpu_percent: b.cpu_usage_percent,
                    mem_used_bytes: b.memory_used_bytes as i64,
                    mem_total_bytes: b.memory_total_bytes as i64,
                    load_1m: b.load_avg_1m,
                    load_5m: b.load_avg_5m,
                    disk_used_bytes: b.disk_used_bytes as i64,
                    disk_total_bytes: b.disk_total_bytes as i64,
                })
                .collect(),
        }),
        Err(e) => internal_error(&e),
    }
}

#[derive(Debug, Deserialize)]
pub struct MetricsQuery {
    pub range: Option<String>,
    pub host: Option<String>,
}

// ---- GET /api/v1/events ----

#[derive(Debug, Serialize)]
pub struct AppEventDto {
    pub id: uuid::Uuid,
    pub app_name: String,
    pub event_type: String,
    pub user_id: Option<String>,
    pub payload: Arc<JsonValue>,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct EventsResponse {
    pub events: Vec<AppEventDto>,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub app: Option<String>,
    #[serde(rename = "type")]
    pub event_type: Option<String>,
    pub range: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// `GET /api/v1/events?app=&type=&range=&limit=&offset=`
///
/// # Errors
/// 400 for out-of-bounds params; 500 on storage failure.
pub async fn get_app_events(
    state: web::Data<ReadState>,
    principal: crate::hub::rest::auth::PrincipalExtractor,
    query: web::Query<EventsQuery>,
) -> HttpResponse {
    if let Some(denied) = require_dashboard(&principal) {
        return denied;
    }

    let Some(range) = MetricRange::parse(query.range.as_deref().unwrap_or("24h")) else {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "range must be one of 1h, 6h, 24h, 7d, 30d"
        }));
    };
    let limit = query.limit.unwrap_or(validate::MAX_LIMIT.min(50));
    let limit = match validate::limit(limit) {
        Ok(limit) => limit,
        Err(reason) => return bad_request(&reason),
    };
    let offset = query.offset.unwrap_or(0);
    let offset = match validate::offset(offset) {
        Ok(offset) => offset,
        Err(reason) => return bad_request(&reason),
    };

    if let Some(app) = &query.app
        && let Err(reason) = validate::app_name(app)
    {
        return bad_request(&reason);
    }
    if let Some(event_type) = &query.event_type
        && let Err(reason) = validate::event_type(event_type, None)
    {
        return bad_request(&reason);
    }

    let filter = EventFilter {
        app_name: query.app.clone(),
        event_type: query.event_type.clone(),
        interval: range.interval(),
        limit,
        offset,
    };

    match state.events.list(&filter).await {
        Ok((rows, total)) => HttpResponse::Ok().json(EventsResponse {
            events: rows
                .into_iter()
                .map(|row: AppEventRow| AppEventDto {
                    id: row.id,
                    app_name: row.app_name,
                    event_type: row.event_type,
                    user_id: row.user_id,
                    payload: Arc::new(row.payload),
                    timestamp: row
                        .timestamp
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                })
                .collect(),
            total,
        }),
        Err(e) => internal_error(&e),
    }
}

// ---- GET /api/v1/servers ----

#[derive(Debug, Serialize)]
pub struct AgentDto {
    pub agent_id: String,
    pub hostname: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub online: bool,
}

#[derive(Debug, Serialize)]
pub struct ServersResponse {
    pub agents: Vec<AgentDto>,
}

/// `GET /api/v1/servers`
///
/// # Errors
/// 500 on storage failure.
pub async fn get_servers(
    state: web::Data<ReadState>,
    principal: crate::hub::rest::auth::PrincipalExtractor,
) -> HttpResponse {
    if let Some(denied) = require_dashboard(&principal) {
        return denied;
    }
    match state.agents.list_with_status(ONLINE_WINDOW_SECS).await {
        Ok(rows) => HttpResponse::Ok().json(ServersResponse {
            agents: rows
                .into_iter()
                .map(|agent: AgentStatus| AgentDto {
                    agent_id: agent.agent_id,
                    hostname: agent.hostname,
                    first_seen_at: agent
                        .first_seen_at
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    last_seen_at: agent
                        .last_seen_at
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    online: agent.online,
                })
                .collect(),
        }),
        Err(e) => internal_error(&e),
    }
}

// ---- GET /api/v1/summary ----

#[derive(Debug, Serialize)]
pub struct SummaryResponse {
    pub active_users_24h: i64,
    pub total_events_24h: i64,
    pub events_by_app: std::collections::HashMap<String, i64>,
    pub events_by_type: std::collections::HashMap<String, i64>,
    pub server_online: bool,
    pub current_cpu_percent: f64,
    pub current_mem_percent: f64,
}

/// `GET /api/v1/summary` — aggregated stats for the dashboard cards.
///
/// # Errors
/// 500 on storage failure.
pub async fn get_summary(
    state: web::Data<ReadState>,
    principal: crate::hub::rest::auth::PrincipalExtractor,
) -> HttpResponse {
    if let Some(denied) = require_dashboard(&principal) {
        return denied;
    }
    let interval = MetricRange::default().interval();

    let summary = async {
        let active_users = state.events.count_active_users(interval).await?;
        let total = state.events.count_total(interval).await?;
        let by_app = state.events.counts_by_app(interval).await?;
        let by_type = state.events.counts_by_type(interval).await?;
        let latest = state.metrics.latest().await?;
        Ok::<_, crate::error::SentinelError>((active_users, total, by_app, by_type, latest))
    };

    match summary.await {
        Ok((active_users, total, by_app, by_type, latest)) => {
            let latest = latest.as_ref();
            let (cpu, mem_percent, online) = match latest {
                Some(metric) => {
                    let mem_percent = if metric.memory_total_bytes > 0 {
                        (metric.memory_used_bytes as f64 / metric.memory_total_bytes as f64) * 100.0
                    } else {
                        0.0
                    };
                    let online =
                        metric.timestamp > chrono::Utc::now() - chrono::Duration::seconds(90);
                    (metric.cpu_usage_percent, mem_percent, online)
                }
                None => (0.0, 0.0, false),
            };
            HttpResponse::Ok().json(SummaryResponse {
                active_users_24h: active_users,
                total_events_24h: total,
                events_by_app: by_app.into_iter().collect(),
                events_by_type: by_type.into_iter().collect(),
                server_online: online,
                current_cpu_percent: cpu,
                current_mem_percent: mem_percent,
            })
        }
        Err(e) => internal_error(&e),
    }
}

// ---- error helpers ----

fn bad_request(reason: &str) -> HttpResponse {
    HttpResponse::BadRequest().json(serde_json::json!({ "error": reason }))
}

fn internal_error(error: &crate::error::SentinelError) -> HttpResponse {
    tracing::error!("read endpoint failure: {error}");
    HttpResponse::InternalServerError().json(serde_json::json!({ "error": "storage failure" }))
}
