//! Repository for agent-reported system metrics.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::error::SentinelError;

/// A stored metric point.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SystemMetricRow {
    pub id: uuid::Uuid,
    pub timestamp: DateTime<Utc>,
    pub cpu_usage_percent: f64,
    pub memory_used_bytes: i64,
    pub memory_total_bytes: i64,
    pub disk_used_bytes: i64,
    pub disk_total_bytes: i64,
    pub load_avg_1m: f64,
    pub load_avg_5m: f64,
    pub network_rx_bytes: i64,
    pub network_tx_bytes: i64,
}

/// A validated metric point ready for insert (trusted boundary from the
/// gRPC handler).
#[derive(Debug, Clone)]
pub struct InsertSystemMetric {
    /// Reporting agent hostname (from the authenticated key row).
    pub host: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub cpu_usage_percent: f64,
    pub memory_used_bytes: i64,
    pub memory_total_bytes: i64,
    pub disk_used_bytes: i64,
    pub disk_total_bytes: i64,
    pub load_avg_1m: f64,
    pub load_avg_5m: f64,
    pub network_rx_bytes: i64,
    pub network_tx_bytes: i64,
}

/// A downsampled point for chart series.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BucketedMetric {
    pub bucket: DateTime<Utc>,
    pub cpu_usage_percent: f64,
    pub memory_used_bytes: f64,
    pub memory_total_bytes: f64,
    pub load_avg_1m: f64,
    pub load_avg_5m: f64,
    pub disk_used_bytes: f64,
    pub disk_total_bytes: f64,
}

#[derive(Clone)]
pub struct SystemMetricRepository {
    pool: PgPool,
}

impl SystemMetricRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Inserts one validated metric point.
    ///
    /// # Errors
    /// Database failure.
    pub async fn insert(&self, metric: &InsertSystemMetric) -> Result<(), SentinelError> {
        sqlx::query(
            r"INSERT INTO system_metrics
                  (host, timestamp, cpu_usage_percent, memory_used_bytes, memory_total_bytes,
                   disk_used_bytes, disk_total_bytes, load_avg_1m, load_avg_5m,
                   network_rx_bytes, network_tx_bytes)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(metric.host.as_deref())
        .bind(metric.timestamp)
        .bind(metric.cpu_usage_percent)
        .bind(metric.memory_used_bytes)
        .bind(metric.memory_total_bytes)
        .bind(metric.disk_used_bytes)
        .bind(metric.disk_total_bytes)
        .bind(metric.load_avg_1m)
        .bind(metric.load_avg_5m)
        .bind(metric.network_rx_bytes)
        .bind(metric.network_tx_bytes)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Downsampled series for charts: buckets by `date_trunc(bucket)`,
    /// averaged, newest last, optionally filtered by reporting host. The
    /// bucket string comes from the `MetricRange` allowlist enum — never
    /// user input — but is still bound as a parameter for the dynamic
    /// bucketed with fixed-width buckets (epoch flooring), so any bucket
    /// width works — `date_trunc` would reject widths like `5 minutes`.
    ///
    /// # Errors
    /// Database failure.
    pub async fn bucketed_series(
        &self,
        interval: &str,
        bucket_seconds: i64,
        max_rows: i64,
        host: Option<&str>,
    ) -> Result<Vec<BucketedMetric>, SentinelError> {
        let rows = sqlx::query_as::<_, BucketedMetric>(
            r"SELECT to_timestamp(
                       FLOOR(EXTRACT(EPOCH FROM timestamp) / $1) * $1
                   ) AS bucket,
                     AVG(cpu_usage_percent)::float8 AS cpu_usage_percent,
                     AVG(memory_used_bytes)::float8 AS memory_used_bytes,
                     AVG(memory_total_bytes)::float8 AS memory_total_bytes,
                     AVG(load_avg_1m)::float8 AS load_avg_1m,
                     AVG(load_avg_5m)::float8 AS load_avg_5m,
                     AVG(disk_used_bytes)::float8 AS disk_used_bytes,
                     AVG(disk_total_bytes)::float8 AS disk_total_bytes
              FROM system_metrics
              WHERE timestamp > NOW() - $2::interval
                AND ($3::text IS NULL OR host = $3)
              GROUP BY bucket
              ORDER BY bucket
              LIMIT $4",
        )
        .bind(bucket_seconds)
        .bind(interval)
        .bind(host)
        .bind(max_rows)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// The most recent metric point (for "current" dashboard cards).
    ///
    /// # Errors
    /// Database failure.
    pub async fn latest(&self) -> Result<Option<SystemMetricRow>, SentinelError> {
        let row = sqlx::query_as::<_, SystemMetricRow>(
            r"SELECT id, timestamp, cpu_usage_percent, memory_used_bytes, memory_total_bytes,
                      disk_used_bytes, disk_total_bytes, load_avg_1m, load_avg_5m,
                      network_rx_bytes, network_tx_bytes
               FROM system_metrics
               ORDER BY timestamp DESC
               LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Deletes metrics older than the retention window. Returns rows deleted.
    ///
    /// # Errors
    /// Database failure.
    pub async fn prune(&self, keep_days: u32) -> Result<u64, SentinelError> {
        let result = sqlx::query(
            r"DELETE FROM system_metrics
              WHERE id IN (
                  SELECT id FROM system_metrics
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
        let _ = SystemMetricRepository::new(pool);
    }
}
