//! `POST /v1/events` — app-event ingestion.
//!
//! The app name comes from the authenticated key row, never the request
//! body. Validation mirrors the hub's rules so callers fail fast, and
//! rejected items are reported with per-item reasons.

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use serde_json::Value as JsonValue;

use crate::db::repositories::app_event_repo::{AppEventRepository, EventFilter, InsertAppEvent};
use crate::hub::auth::Permission;
use crate::hub::rest::auth::EventRateLimiter;
use crate::hub::validate;

/// Request body. Note: no `app_name` — it is derived from the key.
#[derive(Debug, Deserialize)]
pub struct IngestEventsRequest {
    pub events: Vec<IngestEvent>,
}

#[derive(Debug, Deserialize)]
pub struct IngestEvent {
    pub event_type: String,
    pub user_id: Option<String>,
    #[serde(default)]
    pub payload: JsonValue,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Shared handler state.
pub struct EventsState {
    repo: AppEventRepository,
    limiter: EventRateLimiter,
    allowed_event_types: Arc<Vec<String>>,
}

use std::sync::Arc;

impl EventsState {
    #[must_use]
    pub fn new(repo: AppEventRepository, allowed_event_types: Vec<String>) -> Self {
        Self {
            repo,
            limiter: EventRateLimiter::new(100),
            allowed_event_types: Arc::new(allowed_event_types),
        }
    }
}

/// `POST /v1/events`.
///
/// # Errors
/// 401/403 via middleware; 400 for body-level problems; 422 when no event
/// was accepted.
pub async fn post_events(
    state: web::Data<EventsState>,
    principal: crate::hub::rest::auth::PrincipalExtractor,
    body: web::Json<IngestEventsRequest>,
) -> HttpResponse {
    let principal = principal.0;
    if !principal.permissions.contains(&Permission::IngestEvents) {
        return reject_forbidden("key lacks ingest:events");
    }
    let Some(app_name) = principal.app_name.clone() else {
        return reject_forbidden(
            "this key is not bound to an app; app keys are required for event ingestion",
        );
    };

    if !state.limiter.allow(&principal.key_id) {
        return HttpResponse::TooManyRequests()
            .json(serde_json::json!({ "error": "rate limit exceeded" }));
    }

    if body.events.len() > validate::MAX_EVENTS_PER_REQUEST {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!(
                "batch exceeds {} events",
                validate::MAX_EVENTS_PER_REQUEST
            )
        }));
    }

    let mut accepted: Vec<InsertAppEvent> = Vec::with_capacity(body.events.len());
    let mut errors: Vec<serde_json::Value> = Vec::new();
    let allowlist = state.allowed_event_types.as_ref();

    for (index, event) in body.events.iter().enumerate() {
        let result = validate_event(&app_name, event, allowlist);
        match result {
            Ok(insert) => accepted.push(insert),
            Err(reason) => errors.push(serde_json::json!({ "index": index, "reason": reason })),
        }
    }

    if accepted.is_empty() && !errors.is_empty() {
        return HttpResponse::UnprocessableEntity().json(serde_json::json!({
            "accepted": 0,
            "rejected": errors.len(),
            "errors": errors,
        }));
    }

    match state.repo.insert_batch(&accepted).await {
        Ok(inserted) => HttpResponse::Accepted().json(serde_json::json!({
            "accepted": inserted,
            "rejected": errors.len(),
            "errors": errors,
        })),
        Err(e) => {
            tracing::error!("event insert failed: {e}");
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "storage failure" }))
        }
    }
}

/// Validates one event and builds the insert value. The `app_name` always
/// comes from the key — a body-supplied name is never read.
fn validate_event(
    app_name: &str,
    event: &IngestEvent,
    allowlist: &[String],
) -> Result<InsertAppEvent, String> {
    validate::event_type(&event.event_type, Some(allowlist))?;
    if let Some(user_id) = &event.user_id {
        validate::user_id(user_id)?;
    }
    if !event.payload.is_object() {
        return Err("payload must be a JSON object".into());
    }
    let payload_len = serde_json::to_vec(&event.payload).map_or(usize::MAX, |bytes| bytes.len());
    if payload_len > validate::MAX_PAYLOAD_BYTES {
        return Err(format!(
            "payload serialized size {payload_len} exceeds {} bytes",
            validate::MAX_PAYLOAD_BYTES
        ));
    }
    validate::timestamp(event.timestamp, chrono::Utc::now())?;

    Ok(InsertAppEvent {
        app_name: app_name.to_string(),
        event_type: event.event_type.clone(),
        user_id: event.user_id.clone(),
        payload: event.payload.clone(),
        timestamp: event.timestamp,
    })
}

fn reject_forbidden(reason: &str) -> HttpResponse {
    HttpResponse::Forbidden().json(serde_json::json!({ "error": reason }))
}

// Keep the filter type referenced (used by the list endpoint module).
#[allow(dead_code)]
fn _filter_reference(filter: &EventFilter) -> EventFilter {
    filter.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn valid_event() -> IngestEvent {
        IngestEvent {
            event_type: "user_login".into(),
            user_id: Some("u-123".into()),
            payload: serde_json::json!({}),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn validates_good_event() {
        let insert = validate_event("globalware", &valid_event(), &[]).unwrap();
        assert_eq!(insert.app_name, "globalware");
        assert_eq!(insert.event_type, "user_login");
    }

    #[test]
    fn rejects_bad_type() {
        let mut event = valid_event();
        event.event_type = "<script>".into();
        assert!(validate_event("globalware", &event, &[]).is_err());
    }

    #[test]
    fn rejects_non_object_payload() {
        let mut event = valid_event();
        event.payload = serde_json::json!("string");
        assert!(validate_event("globalware", &event, &[]).is_err());
    }

    #[test]
    fn rejects_oversized_payload() {
        let mut event = valid_event();
        event.payload = serde_json::json!({ "blob": "x".repeat(5 * 1024) });
        assert!(validate_event("globalware", &event, &[]).is_err());
    }

    #[test]
    fn allowlist_applies() {
        let allow = vec!["user_login".to_string()];
        assert!(validate_event("globalware", &valid_event(), &allow).is_ok());
        let mut event = valid_event();
        event.event_type = "cart_add".into();
        assert!(validate_event("globalware", &event, &allow).is_err());
    }
}
