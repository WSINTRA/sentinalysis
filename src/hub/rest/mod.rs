//! Actix REST API: ingestion + dashboard read endpoints + static SPA.
//!
//! Middleware chain (outermost first): security headers, key auth, then
//! routes. `GET /api/v1/health` is public; every other route requires an
//! `X-API-KEY` with the right permission.

pub mod auth;
pub mod events;
pub mod headers;
pub mod read;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use actix_files::Files;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::web;
use actix_web::{Error, HttpResponse};
use sqlx::PgPool;

use crate::db::repositories::agent_repo::AgentRepository;
use crate::db::repositories::app_event_repo::AppEventRepository;
use crate::db::repositories::system_metric_repo::SystemMetricRepository;
use crate::hub::auth::AuthService;
use crate::hub::rest::auth::KeyAuth;

/// Builds the actix app config (used inside an `HttpServer` factory
/// closure).
///
/// # Panics
/// Panics if actix's factory is misconfigured; factory closures cannot
/// return errors.
pub fn configure_app(
    cfg: &mut actix_web::web::ServiceConfig,
    pool: PgPool,
    auth: &Arc<AuthService>,
    allowed_event_types: &Arc<Vec<String>>,
    spa_path: PathBuf,
) {
    let events_state = events::EventsState::new(
        AppEventRepository::new(pool.clone()),
        (**allowed_event_types).clone(),
    );
    let read_state = read::ReadState::new(
        SystemMetricRepository::new(pool.clone()),
        AppEventRepository::new(pool.clone()),
        AgentRepository::new(pool),
    );

    cfg.app_data(web::JsonConfig::default().limit(1024 * 1024))
        .app_data(web::Data::new(events_state))
        .app_data(web::Data::new(read_state))
        // Public health probe, deliberately outside the authed scope so
        // load balancers do not need a key (and cannot burn the IP budget).
        .route("/api/v1/health", web::get().to(read::health))
        // Authed ingestion API. Explicit path scopes: a catch-all `scope("")`
        // would shadow the static files below (and put the SPA behind auth).
        .service(
            web::scope("/v1")
                .wrap(headers::SecurityHeaders)
                .wrap(KeyAuth::new(auth.clone()))
                .route("/events", web::post().to(events::post_events)),
        )
        .service(
            web::scope("/api/v1")
                .wrap(headers::SecurityHeaders)
                .wrap(KeyAuth::new(auth.clone()))
                .route("/metrics", web::get().to(read::get_metrics))
                .route("/events", web::get().to(read::get_app_events))
                .route("/servers", web::get().to(read::get_servers))
                .route("/summary", web::get().to(read::get_summary)),
        );

    if spa_path.join("index.html").exists() {
        cfg.service(
            web::scope("").wrap(headers::SecurityHeaders).service(
                Files::new("/", &spa_path)
                    .index_file("index.html")
                    .default_handler(spa_fallback_factory(spa_path)),
            ),
        );
    } else {
        cfg.service(
            web::scope("")
                .wrap(headers::SecurityHeaders)
                .default_service(web::to(spa_placeholder)),
        );
    }
}

/// Builds the SPA fallback service: any unmatched path renders `index.html`.
fn spa_fallback_factory(
    path: PathBuf,
) -> impl Fn(ServiceRequest) -> futures::future::LocalBoxFuture<'static, Result<ServiceResponse, Error>>
+ Clone {
    move |request: ServiceRequest| {
        let path = path.clone();
        Box::pin(async move {
            let index = serve_index(&path);
            let (http_request, _payload) = request.into_parts();
            Ok(ServiceResponse::new(http_request, index))
        })
    }
}

/// Reads `index.html`, falling back to 404 when the SPA is missing files.
fn serve_index(path: &Path) -> HttpResponse {
    match std::fs::read(path.join("index.html")) {
        Ok(bytes) => HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(bytes),
        Err(_) => HttpResponse::NotFound().body("SPA index missing"),
    }
}

/// Placeholder shown when the SPA is not built yet.
async fn spa_placeholder() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(
            "<!doctype html><html><head><title>Sentinel</title></head>\
             <body><h1>Sentinel hub is running</h1>\
             <p>The dashboard SPA is not built yet (web/dist missing).</p>\
             </body></html>",
        )
}
