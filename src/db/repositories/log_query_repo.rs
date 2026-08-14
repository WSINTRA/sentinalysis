//! Read-side queries for the TUI log viewer.
//!
//! All viewer SQL lives here so the TUI never writes queries inline.
//! Ordering is always by `timestamp` — ids are random UUIDs and carry no
//! order. The "entries since last poll" cursor is the `(timestamp, id)`
//! row value of the oldest entry already on screen, so entries sharing a
//! timestamp are neither missed nor duplicated.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::SentinelError;

/// The kind of source a log list in the viewer belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSourceKind {
    /// An nginx virtual host, matched on `services.virtual_host`.
    Vhost,
    /// A plain log file (e.g. `auth.log`), matched on `services.name`
    /// with no virtual host set.
    SystemLog,
}

/// One row of the TUI log list, for either source kind.
#[derive(Debug, Clone, FromRow)]
pub struct LogEntryRow {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
    pub raw_line: Option<String>,
    /// Display name of the source (vhost name or log file name).
    pub source_name: String,
    pub threat_level: String,
    pub threat_categories: Vec<String>,
}

const COUNT_VHOST_SQL: &str = "SELECT s.virtual_host, COUNT(*) AS cnt
FROM log_entries le
JOIN services s ON le.service_id = s.id
WHERE s.virtual_host = ANY($1)
GROUP BY s.virtual_host";

const COUNT_SYSTEM_LOG_SQL: &str = "SELECT s.name, COUNT(*) AS cnt
FROM log_entries le
JOIN services s ON le.service_id = s.id
WHERE s.name = ANY($1) AND s.virtual_host IS NULL
GROUP BY s.name";

const RECENT_VHOST_SQL: &str = "SELECT le.id, le.timestamp, le.level, le.message, le.raw_line,
       s.virtual_host AS source_name, le.threat_level, le.threat_categories
FROM log_entries le
JOIN services s ON le.service_id = s.id
WHERE s.virtual_host = $1
ORDER BY le.timestamp DESC, le.id DESC
LIMIT $2";

const RECENT_SYSTEM_LOG_SQL: &str = "SELECT le.id, le.timestamp, le.level, le.message, le.raw_line,
       s.name AS source_name, le.threat_level, le.threat_categories
FROM log_entries le
JOIN services s ON le.service_id = s.id
WHERE s.name = $1 AND s.virtual_host IS NULL
ORDER BY le.timestamp DESC, le.id DESC
LIMIT $2";

const NEWER_VHOST_SQL: &str = "SELECT le.id, le.timestamp, le.level, le.message, le.raw_line,
       s.virtual_host AS source_name, le.threat_level, le.threat_categories
FROM log_entries le
JOIN services s ON le.service_id = s.id
WHERE s.virtual_host = $1 AND (le.timestamp, le.id) > ($2, $3)
ORDER BY le.timestamp DESC, le.id DESC
LIMIT $4";

const NEWER_SYSTEM_LOG_SQL: &str = "SELECT le.id, le.timestamp, le.level, le.message, le.raw_line,
       s.name AS source_name, le.threat_level, le.threat_categories
FROM log_entries le
JOIN services s ON le.service_id = s.id
WHERE s.name = $1 AND s.virtual_host IS NULL AND (le.timestamp, le.id) > ($2, $3)
ORDER BY le.timestamp DESC, le.id DESC
LIMIT $4";

/// Read queries for the log viewer.
#[derive(Debug, Clone)]
pub struct LogQueryRepository {
    pool: PgPool,
}

impl LogQueryRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Entry counts for the sources panel, keyed by source display name.
    /// Sources with zero entries are absent from the result.
    pub async fn count_entries(
        &self,
        kind: LogSourceKind,
        names: &[String],
    ) -> Result<Vec<(String, i64)>, SentinelError> {
        let sql = match kind {
            LogSourceKind::Vhost => COUNT_VHOST_SQL,
            LogSourceKind::SystemLog => COUNT_SYSTEM_LOG_SQL,
        };
        let rows: Vec<(String, i64)> = sqlx::query_as(sql)
            .bind(names.to_vec())
            .fetch_all(&self.pool)
            .await?;
        Ok(rows)
    }

    /// The most recent `limit` entries for `name`, newest first.
    pub async fn recent_entries(
        &self,
        kind: LogSourceKind,
        name: &str,
        limit: i64,
    ) -> Result<Vec<LogEntryRow>, SentinelError> {
        let sql = match kind {
            LogSourceKind::Vhost => RECENT_VHOST_SQL,
            LogSourceKind::SystemLog => RECENT_SYSTEM_LOG_SQL,
        };
        Ok(sqlx::query_as::<_, LogEntryRow>(sql)
            .bind(name)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?)
    }

    /// Entries strictly newer than the `(since, since_id)` cursor, newest
    /// first, up to `limit`.
    pub async fn newer_entries(
        &self,
        kind: LogSourceKind,
        name: &str,
        since: DateTime<Utc>,
        since_id: Uuid,
        limit: i64,
    ) -> Result<Vec<LogEntryRow>, SentinelError> {
        let sql = match kind {
            LogSourceKind::Vhost => NEWER_VHOST_SQL,
            LogSourceKind::SystemLog => NEWER_SYSTEM_LOG_SQL,
        };
        Ok(sqlx::query_as::<_, LogEntryRow>(sql)
            .bind(name)
            .bind(since)
            .bind(since_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard: viewer ordering must be by timestamp, never by
    /// the random UUID primary key (the old `ORDER BY le.id DESC` showed
    /// entries in arbitrary order).
    #[test]
    fn test_viewer_queries_order_by_timestamp() {
        for sql in [
            RECENT_VHOST_SQL,
            RECENT_SYSTEM_LOG_SQL,
            NEWER_VHOST_SQL,
            NEWER_SYSTEM_LOG_SQL,
        ] {
            assert!(
                sql.contains("ORDER BY le.timestamp DESC, le.id DESC"),
                "missing timestamp ordering in: {sql}"
            );
        }
    }

    /// The poll cursor must be a `(timestamp, id)` row value so that
    /// entries sharing a timestamp are neither missed nor duplicated.
    #[test]
    fn test_newer_queries_use_row_value_cursor() {
        for sql in [NEWER_VHOST_SQL, NEWER_SYSTEM_LOG_SQL] {
            assert!(
                sql.contains("(le.timestamp, le.id) > ($2, $3)"),
                "missing row-value cursor in: {sql}"
            );
        }
    }
}
