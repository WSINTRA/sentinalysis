//! Daily retention pruning for hub tables.
//!
//! Event payloads carry PII (cart contents, user IDs), so retention is a
//! security control, not just housekeeping. Deletes run in batches to
//! avoid long locks on a small (2GB) database.

use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

use crate::config::HubConfig;
use crate::db::repositories::log_entry_repo::prune_log_entries;
use crate::error::SentinelError;

/// The retention loop: prunes once at startup, then daily.
///
/// # Errors
/// Never returns an error; failures are logged and retried next cycle.
pub async fn run(pool: PgPool, hub: HubConfig, cancel: CancellationToken) {
    let mut interval = tokio::time::interval(std::time::Duration::new(24 * 3600, 0));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            _ = interval.tick() => {
                if let Err(e) = prune_all(&pool, &hub).await {
                    tracing::warn!("retention prune failed: {e}");
                }
            }
        }
    }
}

/// One prune pass over every retention-scoped table.
///
/// # Errors
/// Database failures propagate for the caller to log.
pub async fn prune_all(pool: &PgPool, hub: &HubConfig) -> Result<(), SentinelError> {
    if hub.retention_days > 0 {
        let events = crate::db::repositories::app_event_repo::AppEventRepository::new(pool.clone())
            .prune(hub.retention_days)
            .await?;
        let logs = prune_log_entries(pool, hub.retention_days).await?;
        tracing::info!(
            days = hub.retention_days,
            app_events = events,
            log_entries = logs,
            "retention prune complete"
        );
    }
    if hub.metrics_retention_days > 0 {
        let metrics =
            crate::db::repositories::system_metric_repo::SystemMetricRepository::new(pool.clone())
                .prune(hub.metrics_retention_days)
                .await?;
        tracing::info!(
            days = hub.metrics_retention_days,
            system_metrics = metrics,
            "metric retention prune complete"
        );
    }
    Ok(())
}
