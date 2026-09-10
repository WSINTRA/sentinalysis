//! Repository for app events forwarded by web applications.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::PgPool;

use crate::error::SentinelError;

/// A stored app event.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AppEventRow {
    pub id: uuid::Uuid,
    pub app_name: String,
    pub event_type: String,
    pub user_id: Option<String>,
    pub payload: JsonValue,
    pub timestamp: DateTime<Utc>,
}

/// A validated event ready for insert. The caller (REST handler) validates
/// everything; this type is the trusted boundary into the repository.
#[derive(Debug, Clone)]
pub struct InsertAppEvent {
    pub app_name: String,
    pub event_type: String,
    pub user_id: Option<String>,
    pub payload: JsonValue,
    pub timestamp: DateTime<Utc>,
}

/// Filters for list queries; all values are bound as parameters.
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    pub app_name: Option<String>,
    pub event_type: Option<String>,
    /// SQL interval fragment comes from the `MetricRange` allowlist enum —
    /// never user input.
    pub interval: &'static str,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Clone)]
pub struct AppEventRepository {
    pool: PgPool,
}

impl AppEventRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Inserts a batch of validated events in one statement.
    ///
    /// # Errors
    /// Database failure (a constraint violation rejects the whole batch).
    pub async fn insert_batch(&self, events: &[InsertAppEvent]) -> Result<usize, SentinelError> {
        if events.is_empty() {
            return Ok(0);
        }
        let mut query_builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "INSERT INTO app_events (app_name, event_type, user_id, payload, timestamp)",
        );
        query_builder.push_values(events, |mut bind, event| {
            bind.push_bind(&event.app_name);
            bind.push_bind(&event.event_type);
            bind.push_bind(event.user_id.as_deref());
            bind.push_bind(&event.payload);
            bind.push_bind(event.timestamp);
        });
        let result = query_builder.build().execute(&self.pool).await?;
        Ok(usize::try_from(result.rows_affected()).unwrap_or_default())
    }

    /// Lists events matching the filter, newest first, with a total count.
    ///
    /// # Errors
    /// Database failure.
    pub async fn list(
        &self,
        filter: &EventFilter,
    ) -> Result<(Vec<AppEventRow>, i64), SentinelError> {
        let total = sqlx::query_scalar::<_, i64>(
            r"SELECT COUNT(*) FROM app_events
              WHERE timestamp > NOW() - $1::interval
                AND ($2::text IS NULL OR app_name = $2)
                AND ($3::text IS NULL OR event_type = $3)",
        )
        .bind(filter.interval)
        .bind(filter.app_name.as_deref())
        .bind(filter.event_type.as_deref())
        .fetch_one(&self.pool)
        .await?;

        let events = sqlx::query_as::<_, AppEventRow>(
            r"SELECT id, app_name, event_type, user_id, payload, timestamp
              FROM app_events
              WHERE timestamp > NOW() - $1::interval
                AND ($2::text IS NULL OR app_name = $2)
                AND ($3::text IS NULL OR event_type = $3)
              ORDER BY timestamp DESC, id
              LIMIT $4 OFFSET $5",
        )
        .bind(filter.interval)
        .bind(filter.app_name.as_deref())
        .bind(filter.event_type.as_deref())
        .bind(filter.limit)
        .bind(filter.offset)
        .fetch_all(&self.pool)
        .await?;

        Ok((events, total))
    }

    /// Distinct users who logged in within the interval (the dashboard's
    /// "active users" metric).
    ///
    /// # Errors
    /// Database failure.
    pub async fn count_active_users(&self, interval: &str) -> Result<i64, SentinelError> {
        let count = sqlx::query_scalar::<_, i64>(
            r"SELECT COUNT(DISTINCT user_id) FROM app_events
              WHERE event_type = 'user_login'
                AND user_id IS NOT NULL
                AND timestamp > NOW() - $1::interval",
        )
        .bind(interval)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    /// Total events within the interval.
    ///
    /// # Errors
    /// Database failure.
    pub async fn count_total(&self, interval: &str) -> Result<i64, SentinelError> {
        let count = sqlx::query_scalar::<_, i64>(
            r"SELECT COUNT(*) FROM app_events WHERE timestamp > NOW() - $1::interval",
        )
        .bind(interval)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    /// Event counts grouped by app name within the interval.
    ///
    /// # Errors
    /// Database failure.
    pub async fn counts_by_app(&self, interval: &str) -> Result<Vec<(String, i64)>, SentinelError> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            r"SELECT app_name, COUNT(*) FROM app_events
              WHERE timestamp > NOW() - $1::interval
              GROUP BY app_name ORDER BY COUNT(*) DESC",
        )
        .bind(interval)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Event counts grouped by event type within the interval.
    ///
    /// # Errors
    /// Database failure.
    pub async fn counts_by_type(
        &self,
        interval: &str,
    ) -> Result<Vec<(String, i64)>, SentinelError> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            r"SELECT event_type, COUNT(*) FROM app_events
              WHERE timestamp > NOW() - $1::interval
              GROUP BY event_type ORDER BY COUNT(*) DESC",
        )
        .bind(interval)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Deletes events older than the retention window. Returns rows deleted.
    ///
    /// # Errors
    /// Database failure.
    pub async fn prune(&self, keep_days: u32) -> Result<u64, SentinelError> {
        let result = sqlx::query(
            r"DELETE FROM app_events
              WHERE id IN (
                  SELECT id FROM app_events
                  WHERE timestamp < NOW() - make_interval(days => $1)
                  LIMIT 10000
              )",
        )
        .bind(keep_days.cast_signed())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn constructs_with_lazy_pool() {
        let pool = PgPool::connect_lazy("postgresql://test:test@localhost/none").unwrap();
        let _ = AppEventRepository::new(pool);
    }

    #[test]
    fn event_filter_defaults() {
        let filter = EventFilter {
            interval: "24 hours",
            limit: 50,
            ..Default::default()
        };
        assert_eq!(filter.limit, 50);
        assert!(filter.app_name.is_none());
    }
}
