//! End-to-end hub test against a live Postgres.
//!
//! Covers: migrations on a fresh DB, key creation, key auth (format →
//! cache → indexed lookup → argon2), the gRPC ingestion round-trip
//! (metrics + logs), REST event ingestion with per-role enforcement,
//! dashboard read endpoints, key revocation, and retention pruning.
//!
//! Database: `E2E_DATABASE_URL`, defaulting to
//! `postgres://postgres:sentinel@localhost:55432/sentinel_e2e`
//! (`docker run -d --name sentinel-e2e -e POSTGRES_PASSWORD=sentinel
//! -e POSTGRES_DB=sentinel_e2e -p 55432:5432 postgres:16-alpine`).
//! Skips gracefully (passes) when the database is unreachable so
//! `cargo test` stays green without Docker.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use actix_web::test;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use sentinel::agent::HubClient;
use sentinel::config::{AgentConfig, HubConfig};
use sentinel::db::models::InsertLogEntry;
use sentinel::db::repositories::agent_repo::AgentRepository;
use sentinel::db::repositories::api_key_repo::{ApiKeyRepository, InsertApiKey};
use sentinel::db::repositories::app_event_repo::{AppEventRepository, EventFilter, InsertAppEvent};
use sentinel::db::repositories::log_entry_repo::LogEntryRepository;
use sentinel::db::repositories::system_metric_repo::{InsertSystemMetric, SystemMetricRepository};
use sentinel::hub::auth::{AuthError, AuthService, generate_key, hash_key};
use sentinel::hub::grpc::IngestService;
use sentinel::hub::pb::ingest_client::IngestClient;
use sentinel::hub::pb::ingest_server::IngestServer;
use sentinel::hub::pb::{LogLine, MetricPoint, MetricsRequest};
use sentinel::hub::rest;
use sentinel::hub::retention;

const DEFAULT_E2E_URL: &str = "postgres://postgres:sentinel@localhost:55432/sentinel_e2e";

async fn connect_pool() -> Option<PgPool> {
    let url = std::env::var("E2E_DATABASE_URL").unwrap_or_else(|_| DEFAULT_E2E_URL.into());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&url);
    match tokio::time::timeout(Duration::from_secs(3), pool).await {
        Ok(Ok(pool)) => Some(pool),
        _ => None,
    }
}

/// The whole hub flow, sequentially. One function so the shared hub
/// tables are never touched by parallel test threads.
#[allow(clippy::too_many_lines)] // one sequential scenario, intentionally long
#[tokio::test(flavor = "multi_thread")]
async fn test_hub_end_to_end() {
    let Some(pool) = connect_pool().await else {
        eprintln!("skipping hub e2e: no Postgres reachable (start the sentinel-e2e container)");
        return;
    };

    sentinel::hub::run_hub::run_migrations(&pool)
        .await
        .expect("migrations must succeed");

    let suffix = Uuid::new_v4().simple().to_string()[..8].to_string();
    let hostname = format!("e2e-host-{suffix}");
    let agent_id = format!("e2e-agent-{suffix}");
    let app_name = format!("e2e-shop-{suffix}");
    let container = format!("e2e-container-{suffix}");

    // ---- keys ----------------------------------------------------------
    let keys = ApiKeyRepository::new(pool.clone());
    let (agent_raw, agent_key_id) = generate_key();
    let (app_raw, app_key_id) = generate_key();
    let (dash_raw, dash_key_id) = generate_key();

    keys.create(&InsertApiKey {
        name: format!("e2e agent {suffix}"),
        hash: hash_key(&agent_raw).unwrap(),
        permissions: vec!["ingest:metrics".into(), "ingest:logs".into()],
        key_id: agent_key_id.clone(),
        agent_id: Some(agent_id.clone()),
        hostname: Some(hostname.clone()),
        app_name: None,
    })
    .await
    .expect("agent key creation");
    keys.create(&InsertApiKey {
        name: format!("e2e app {suffix}"),
        hash: hash_key(&app_raw).unwrap(),
        permissions: vec!["ingest:events".into()],
        key_id: app_key_id.clone(),
        agent_id: None,
        hostname: None,
        app_name: Some(app_name.clone()),
    })
    .await
    .expect("app key creation");
    keys.create(&InsertApiKey {
        name: format!("e2e dashboard {suffix}"),
        hash: hash_key(&dash_raw).unwrap(),
        permissions: vec!["read:dashboard".into()],
        key_id: dash_key_id.clone(),
        agent_id: None,
        hostname: None,
        app_name: None,
    })
    .await
    .expect("dashboard key creation");

    // ---- auth service: the full verification path ----------------------
    let auth = AuthService::new(ApiKeyRepository::new(pool.clone()));
    // Negative paths first: the first success caches the key for 60s, so
    // a bad-secret probe after that would be served from cache (by design).
    let bad = format!("{}_", &agent_raw[..agent_raw.len() - 1]);
    assert!(
        matches!(
            auth.authenticate("snt_zzzzzzzz_not-a-valid-format!!").await,
            Err(AuthError::Malformed)
        ),
        "garbage keys must be rejected before any DB work"
    );
    let (unknown_raw, _unknown_id) = generate_key();
    assert!(
        matches!(
            auth.authenticate(&unknown_raw).await,
            Err(AuthError::UnknownKey)
        ),
        "well-formed but unregistered key_id must be rejected"
    );
    assert!(
        matches!(auth.authenticate(&bad).await, Err(AuthError::BadSignature)),
        "wrong secret must fail argon2"
    );

    let agent_principal = auth
        .authenticate(&agent_raw)
        .await
        .expect("agent key verifies");
    assert_eq!(agent_principal.agent_id, Some(agent_id.clone()));
    assert_eq!(agent_principal.hostname, Some(hostname.clone()));

    // ---- gRPC: real server on an ephemeral port ------------------------
    let grpc_port = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let service = IngestServer::new(IngestService::new(pool.clone()));
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
        );
        port
    };

    let agent_config = AgentConfig {
        hub_addr: format!("127.0.0.1:{grpc_port}"),
        api_key: agent_raw.clone(),
        ..AgentConfig::default()
    };
    let cancel = tokio_util::sync::CancellationToken::new();
    let mut client = HubClient::connect(&agent_config, &cancel)
        .await
        .expect("agent connects to hub");
    let now_ms = chrono::Utc::now().timestamp_millis();

    client
        .send_metrics(MetricPoint {
            timestamp_ms: now_ms,
            cpu_percent: 42.5,
            mem_used_bytes: 1_000_000_000,
            mem_total_bytes: 2_000_000_000,
            disk_used_bytes: 10_000_000_000,
            disk_total_bytes: 40_000_000_000,
            load_1m: 1.5,
            load_5m: 2.5,
            net_rx_bytes_total: 100,
            net_tx_bytes_total: 200,
        })
        .await
        .expect("metrics accepted");

    client
        .send_logs(vec![
            LogLine {
                timestamp_ms: now_ms,
                container: container.clone(),
                stream: "stdout".into(),
                message: format!("e2e-log-stdout-{suffix}"),
            },
            LogLine {
                timestamp_ms: now_ms,
                container: container.clone(),
                stream: "stderr".into(),
                message: format!("e2e-log-stderr-{suffix}"),
            },
        ])
        .await
        .expect("logs accepted");

    // Rows must be visible in Postgres, scoped to the key's hostname.
    let (metric_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM system_metrics WHERE host = $1")
            .bind(&hostname)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(metric_count, 1, "exactly one metric row for the e2e host");

    let (log_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM log_entries WHERE raw_line LIKE $1")
            .bind(format!("e2e-log-%-{suffix}"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(log_count, 2, "both log lines stored");

    let (stderr_level,): (String,) =
        sqlx::query_as("SELECT level FROM log_entries WHERE raw_line = $1")
            .bind(format!("e2e-log-stderr-{suffix}"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stderr_level, "error", "stderr lines store as error level");

    let agents = AgentRepository::new(pool.clone())
        .list_with_status(90)
        .await
        .unwrap();
    let registered = agents
        .iter()
        .find(|a| a.agent_id == agent_id)
        .expect("agent registered in the agents table");
    assert_eq!(registered.hostname, hostname);
    assert!(registered.online, "fresh upsert means the agent is online");

    // gRPC auth failures.
    let mut anonymous = IngestClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();
    let unauthenticated = anonymous
        .send_metrics(tonic::Request::new(MetricsRequest { point: None }))
        .await
        .unwrap_err();
    assert_eq!(
        unauthenticated.code(),
        tonic::Code::Unauthenticated,
        "missing x-api-key must be rejected"
    );

    let mut impostor = IngestClient::connect(format!("http://127.0.0.1:{grpc_port}"))
        .await
        .unwrap();
    let denied = wrong_key_request(&mut impostor, &dash_raw).await;
    assert_eq!(
        denied.code(),
        tonic::Code::PermissionDenied,
        "dashboard keys cannot ingest via gRPC"
    );

    // ---- REST -----------------------------------------------------------
    let rest_auth = Arc::new(AuthService::new(ApiKeyRepository::new(pool.clone())));
    let allowed = Arc::new(vec!["user_login".to_string(), "purchase".to_string()]);
    let spa = PathBuf::from("target/e2e-no-spa");
    let app = test::init_service(actix_web::App::new().configure({
        let pool = pool.clone();
        move |cfg| rest::configure_app(cfg, pool, &rest_auth, &allowed, spa.clone())
    }))
    .await;

    // Health is public: no key, no auth limiter hit.
    let response = test::call_service(
        &app,
        test::TestRequest::get().uri("/api/v1/health").to_request(),
    )
    .await;
    assert_eq!(response.status(), actix_web::http::StatusCode::OK);

    // App key posts events; app_name comes from the key, not the body.
    let body = json!({
        "events": [
            {
                "event_type": "user_login",
                "user_id": "u-e2e",
                "payload": { "cart": 2 },
                "timestamp": chrono::Utc::now().to_rfc3339()
            },
            {
                "event_type": "DROP TABLE users;--",
                "payload": {},
                "timestamp": chrono::Utc::now().to_rfc3339()
            }
        ]
    });
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/v1/events")
            .insert_header(("X-API-KEY", app_raw.clone()))
            .set_json(&body)
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), actix_web::http::StatusCode::ACCEPTED);
    let result: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(result["accepted"], 1, "one valid event accepted");
    assert_eq!(
        result["rejected"], 1,
        "the SQL-injection-looking type rejected"
    );

    // The stored event is scoped to the key's app, never the body's.
    let (rows, total) = AppEventRepository::new(pool.clone())
        .list(&EventFilter {
            app_name: Some(app_name.clone()),
            event_type: None,
            interval: "1 hour",
            limit: 50,
            offset: 0,
        })
        .await
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(rows[0].event_type, "user_login");
    assert_eq!(rows[0].app_name, app_name);

    // Wrong role bindings are rejected.
    for (raw, expected) in [(&agent_raw, "agent key"), (&dash_raw, "dashboard key")] {
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/v1/events")
                .insert_header(("X-API-KEY", raw.clone()))
                .set_json(&body)
                .to_request(),
        )
        .await;
        assert_eq!(
            response.status(),
            actix_web::http::StatusCode::FORBIDDEN,
            "{expected} must not ingest events"
        );
    }
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/v1/events")
            .insert_header(("X-API-KEY", "snt_00000000_garbagegarbagegarbage"))
            .set_json(&body)
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), actix_web::http::StatusCode::UNAUTHORIZED);

    // Read endpoints: dashboard key only.
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/api/v1/events?app={app_name}"))
            .insert_header(("X-API-KEY", dash_raw.clone()))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), actix_web::http::StatusCode::OK);
    let listing: serde_json::Value = test::read_body_json(response).await;
    assert!(
        listing["total"].as_i64().unwrap() >= 1,
        "the e2e event is listed"
    );

    for uri in ["/api/v1/summary", "/api/v1/servers", "/api/v1/metrics"] {
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(uri)
                .insert_header(("X-API-KEY", dash_raw.clone()))
                .to_request(),
        )
        .await;
        assert_eq!(
            response.status(),
            actix_web::http::StatusCode::OK,
            "GET {uri} with dashboard key"
        );
    }
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/summary")
            .insert_header(("X-API-KEY", app_raw.clone()))
            .to_request(),
    )
    .await;
    assert_eq!(
        response.status(),
        actix_web::http::StatusCode::FORBIDDEN,
        "app keys cannot read the dashboard"
    );

    // ---- revocation ------------------------------------------------------
    assert!(keys.revoke(&agent_key_id).await.unwrap(), "revoke succeeds");
    assert!(
        !keys.revoke(&agent_key_id).await.unwrap(),
        "double revoke is false"
    );
    assert!(
        keys.find_active_by_key_id(&agent_key_id)
            .await
            .unwrap()
            .is_none(),
        "revoked key no longer active"
    );
    auth.invalidate(&agent_key_id).await;
    assert!(
        matches!(
            auth.authenticate(&agent_raw).await,
            Err(AuthError::UnknownKey)
        ),
        "revoked + invalidated key must not authenticate"
    );

    // ---- retention -------------------------------------------------------
    let old = chrono::Utc::now() - chrono::Duration::days(40);
    let ancient = chrono::Utc::now() - chrono::Duration::days(100);
    SystemMetricRepository::new(pool.clone())
        .insert(&InsertSystemMetric {
            host: Some(hostname.clone()),
            timestamp: old,
            cpu_usage_percent: 1.0,
            memory_used_bytes: 1,
            memory_total_bytes: 2,
            disk_used_bytes: 3,
            disk_total_bytes: 4,
            load_avg_1m: 0.0,
            load_avg_5m: 0.0,
            network_rx_bytes: 0,
            network_tx_bytes: 0,
        })
        .await
        .unwrap();
    AppEventRepository::new(pool.clone())
        .insert_batch(&[InsertAppEvent {
            app_name: app_name.clone(),
            event_type: "user_login".into(),
            user_id: Some("u-old".into()),
            payload: json!({}),
            timestamp: ancient,
        }])
        .await
        .unwrap();
    LogEntryRepository::new(pool.clone())
        .insert_batch(&[InsertLogEntry {
            service_id: None,
            timestamp: ancient,
            level: "info".into(),
            message: format!("e2e-ancient-{suffix}"),
            raw_line: Some(format!("e2e-ancient-{suffix}")),
            client_ip: None,
            request_path: None,
            status_code: None,
            response_time_ms: None,
            is_noise: false,
            noise_reason: None,
            threat_level: "none".into(),
            threat_categories: vec![],
        }])
        .await
        .unwrap();

    let hub = HubConfig {
        retention_days: 90,
        metrics_retention_days: 30,
        ..HubConfig::default()
    };
    retention::prune_all(&pool, &hub).await.unwrap();

    let (old_metrics,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM system_metrics WHERE host = $1 AND timestamp < NOW() - INTERVAL '30 days'",
    )
    .bind(&hostname)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(old_metrics, 0, "metrics older than 30 days pruned");

    let (old_events,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM app_events WHERE app_name = $1 AND timestamp < NOW() - INTERVAL '90 days'",
    )
    .bind(&app_name)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(old_events, 0, "events older than 90 days pruned");

    let (old_logs,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM log_entries WHERE raw_line LIKE $1")
            .bind("e2e-ancient-%".to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(old_logs, 0, "logs older than 90 days pruned");

    // Recent data survives the prune.
    let (recent_events,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM app_events WHERE app_name = $1")
            .bind(&app_name)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(recent_events, 1, "fresh event survives retention");
}

/// Helper: sends a metric-less request under `raw_key`, returns the error.
async fn wrong_key_request(
    client: &mut IngestClient<tonic::transport::Channel>,
    raw_key: &str,
) -> tonic::Status {
    let mut request = tonic::Request::new(MetricsRequest { point: None });
    request
        .metadata_mut()
        .insert("x-api-key", raw_key.parse().unwrap());
    client.send_metrics(request).await.unwrap_err()
}
