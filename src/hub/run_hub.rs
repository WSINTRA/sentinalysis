//! Hub startup: migrations, gRPC server, REST server, retention, signals.

use std::net::SocketAddr;
use std::sync::Arc;

use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

use crate::db::repositories::api_key_repo::ApiKeyRepository;
use crate::error::SentinelError;
use crate::hub::auth::AuthService;
use crate::hub::grpc::IngestService;
use crate::hub::pb::ingest_server::IngestServer;
use crate::hub::rest;
use crate::hub::retention;

/// Runs the hub until SIGINT/SIGTERM.
///
/// # Errors
/// Config or database failures, TLS misconfiguration, bind failures.
pub async fn run(pool: PgPool, config: crate::config::Config) -> Result<(), SentinelError> {
    let hub = &config.hub;
    if !hub.enabled {
        return Err(SentinelError::ConfigError(
            "hub mode requested but hub.enabled is false in the config".into(),
        ));
    }
    hub.validate_bind_security()?;
    run_migrations(&pool).await?;

    let auth = Arc::new(AuthService::new(ApiKeyRepository::new(pool.clone())));
    let cancel = CancellationToken::new();

    // gRPC ingestion server.
    let grpc_addr = resolve_addr(&hub.grpc_host, hub.grpc_port)?;
    let grpc_service = IngestServer::new(IngestService::new(pool.clone()));
    let grpc_task = spawn_grpc(grpc_addr, grpc_service, cancel.clone());

    // REST API + static SPA.
    let rest_addr = resolve_addr(&hub.rest_host, hub.rest_port)?;
    let rest_task = spawn_rest(
        pool.clone(),
        &auth,
        &Arc::new(hub.allowed_event_types.clone()),
        hub.spa_path.clone(),
        rest_addr,
        cancel.clone(),
    );

    // Daily retention prune.
    let retention_task = tokio::spawn(retention::run(pool.clone(), hub.clone(), cancel.clone()));

    tracing::info!(
        grpc = %grpc_addr,
        rest = %rest_addr,
        "hub listening"
    );

    // Wait for SIGINT/SIGTERM, then cancel all tasks.
    tokio::select! {
        () = wait_for_shutdown() => {}
        () = cancel.cancelled() => {}
    }
    cancel.cancel();
    tracing::info!("hub shutting down");

    // Await task ends; individual task errors are logged, not fatal.
    for (name, task) in [
        ("grpc", grpc_task),
        ("rest", rest_task),
        ("retention", retention_task),
    ] {
        if let Err(join_error) = task.await {
            tracing::warn!(task = name, "hub task join failed: {join_error}");
        }
    }
    Ok(())
}

/// Applies all migrations so a fresh Postgres is usable without manual
/// setup.
///
/// # Errors
/// Database or migration failure.
pub async fn run_migrations(pool: &PgPool) -> Result<(), SentinelError> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| SentinelError::DatabaseError(sqlx::Error::from(e)))
}

fn resolve_addr(host: &str, port: u16) -> Result<SocketAddr, SentinelError> {
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()
        .map_err(|e| SentinelError::ConfigError(format!("invalid hub address {host}:{port}: {e}")))?
        .next()
        .ok_or_else(|| SentinelError::ConfigError(format!("hub address {host}:{port} unresolved")))
}

/// SIGINT + SIGTERM, same pattern as the daemon.
async fn wait_for_shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

/// Spawns the tonic server; shutdown is handled by process exit.
fn spawn_grpc(
    addr: SocketAddr,
    service: IngestServer<IngestService>,
    _cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let server = tonic::transport::Server::builder().add_service(service);
        // TLS is planned; v1 relies on the bind-security guard refusing
        // public plaintext binds (loopback/Tailscale only).
        if let Err(e) = server.serve(addr).await {
            tracing::error!("gRPC server failed: {e}");
        }
    })
}

/// Spawns the actix HTTP server on a dedicated thread (actix owns its own
/// runtime); shutdown is handled by process exit.
fn spawn_rest(
    pool: PgPool,
    auth: &Arc<AuthService>,
    allowed_event_types: &Arc<Vec<String>>,
    spa_path: std::path::PathBuf,
    addr: SocketAddr,
    _cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let auth = auth.clone();
    let allowed_event_types = allowed_event_types.clone();
    tokio::task::spawn_blocking(move || {
        let result = actix_web::rt::System::new().block_on(async move {
            let server = actix_web::HttpServer::new(move || {
                let pool = pool.clone();
                let auth = auth.clone();
                let allowed = allowed_event_types.clone();
                let spa_path = spa_path.clone();
                actix_web::App::new().configure(move |cfg| {
                    rest::configure_app(cfg, pool.clone(), &auth, &allowed, spa_path.clone());
                })
            })
            .workers(2)
            .disable_signals();

            match server.bind(addr) {
                Ok(bound) => bound.run().await,
                Err(e) => Err(std::io::Error::other(e.to_string())),
            }
        });
        if let Err(e) = result {
            tracing::error!("REST server failed: {e}");
        }
    })
}
