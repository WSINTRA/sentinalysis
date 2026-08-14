use sqlx::PgPool;

use crate::db::models::InsertLogEntry;
use crate::error::SentinelError;

pub struct LogEntryRepository {
    pool: PgPool,
}

impl LogEntryRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[allow(clippy::cast_possible_truncation)]
    pub async fn insert_batch(&self, entries: &[InsertLogEntry]) -> Result<usize, SentinelError> {
        if entries.is_empty() {
            return Ok(0);
        }

        let mut total_inserted = 0;

        for entry in entries {
            let result = sqlx::query(
                r"INSERT INTO log_entries (service_id, timestamp, level, message, raw_line, client_ip, request_path, status_code, response_time_ms, is_noise, noise_reason) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            )
            .bind(entry.service_id)
            .bind(entry.timestamp)
            .bind(&entry.level)
            .bind(&entry.message)
            .bind(entry.raw_line.as_deref())
            .bind(entry.client_ip.as_deref())
            .bind(entry.request_path.as_deref())
            .bind(entry.status_code)
            .bind(entry.response_time_ms)
            .bind(entry.is_noise)
            .bind(entry.noise_reason.as_deref())
            .execute(&self.pool)
            .await?;

            total_inserted += result.rows_affected() as usize;
        }

        Ok(total_inserted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
