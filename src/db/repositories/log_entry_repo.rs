//! Write-side persistence for `log_entries`.
//!
//! The scanner flushes batches through [`LogEntryRepository::insert_batch`],
//! which issues one multi-row `INSERT` per batch regardless of batch size.

use sqlx::postgres::Postgres;
use sqlx::{PgPool, QueryBuilder};

use crate::db::models::InsertLogEntry;
use crate::error::SentinelError;

const INSERT_PREFIX: &str = "INSERT INTO log_entries (service_id, timestamp, level, message, raw_line, client_ip, request_path, status_code, response_time_ms, is_noise, noise_reason, threat_level, threat_categories, source_host)";

/// Persistence for `log_entries`.
#[derive(Clone)]
pub struct LogEntryRepository {
    pool: PgPool,
}

impl LogEntryRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a batch of entries in a single multi-row `INSERT`.
    pub async fn insert_batch(&self, entries: &[InsertLogEntry]) -> Result<usize, SentinelError> {
        if entries.is_empty() {
            return Ok(0);
        }

        let result = build_insert_query(entries)
            .build()
            .execute(&self.pool)
            .await?;

        // The DB reports one affected row per inserted entry; clamp
        // rather than assume the target pointer width.
        Ok(usize::try_from(result.rows_affected()).unwrap_or(usize::MAX))
    }
}

/// Build the multi-row insert. One set of 14 bind placeholders per entry,
/// so a batch of N entries is a single round-trip.
pub(crate) fn build_insert_query(entries: &[InsertLogEntry]) -> QueryBuilder<'_, Postgres> {
    let mut query = QueryBuilder::new(INSERT_PREFIX);

    // `push_values` supplies the `VALUES` keyword and the `), (` between
    // tuples; `push_bind` separates the columns within a tuple.
    query.push_values(entries.iter(), |mut q, entry| {
        q.push_bind(entry.service_id)
            .push_bind(entry.timestamp)
            .push_bind(&entry.level)
            .push_bind(&entry.message)
            .push_bind(entry.raw_line.as_deref())
            .push_bind(entry.client_ip.as_deref())
            .push_bind(entry.request_path.as_deref())
            .push_bind(entry.status_code)
            .push_bind(entry.response_time_ms)
            .push_bind(entry.is_noise)
            .push_bind(entry.noise_reason.as_deref())
            .push_bind(&entry.threat_level)
            .push_bind(&entry.threat_categories)
            .push_bind(entry.source_host.as_deref());
    });

    query
}

/// Deletes log entries older than the retention window, in bounded batches.
/// Returns rows deleted. Free function: the hub's retention loop uses it
/// without holding a repository instance.
///
/// # Errors
/// Database failure.
pub async fn prune_log_entries(pool: &PgPool, keep_days: u32) -> Result<u64, SentinelError> {
    let result = sqlx::query(
        r"DELETE FROM log_entries
          WHERE id IN (
              SELECT id FROM log_entries
              WHERE timestamp < NOW() - make_interval(days => $1)
              LIMIT 10000
          )",
    )
    .bind(keep_days.cast_signed())
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sqlx::Execute;

    fn sample_entry(i: u64) -> InsertLogEntry {
        InsertLogEntry {
            service_id: None,
            timestamp: Utc::now(),
            level: "info".to_string(),
            message: format!("entry {i}"),
            raw_line: Some(format!("raw {i}")),
            client_ip: None,
            request_path: None,
            status_code: None,
            response_time_ms: None,
            is_noise: false,
            noise_reason: None,
            threat_level: "none".to_string(),
            threat_categories: vec![],
            source_host: None,
        }
    }

    #[tokio::test]
    async fn test_log_entry_repository_creation() {
        let pool = PgPool::connect_lazy("postgresql://test:test@localhost/test").unwrap();
        let repo = LogEntryRepository::new(pool);
        let _ = &repo;
    }

    #[tokio::test]
    async fn test_insert_batch_empty_returns_zero() {
        let pool = PgPool::connect_lazy("postgresql://test:test@localhost/test").unwrap();
        let repo = LogEntryRepository::new(pool);
        let entries: Vec<InsertLogEntry> = vec![];

        let result = repo.insert_batch(&entries).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    /// The SQL shape is inspectable without a database: 14 binds per
    /// entry, numbered sequentially in one statement.
    #[test]
    fn test_build_insert_query_one_statement_per_batch() {
        let sql_one = build_insert_query(&[sample_entry(0)])
            .build()
            .sql()
            .to_string();
        assert!(sql_one.contains("$14"), "14 binds for one entry: {sql_one}");
        assert!(!sql_one.contains("$15"));

        let sql_two = build_insert_query(&[sample_entry(0), sample_entry(1)])
            .build()
            .sql()
            .to_string();
        assert!(
            sql_two.contains("$28"),
            "28 binds for two entries: {sql_two}"
        );
        assert!(!sql_two.contains("$29"));
        // One INSERT, not N.
        assert_eq!(sql_two.matches("INSERT INTO").count(), 1);
    }
}
