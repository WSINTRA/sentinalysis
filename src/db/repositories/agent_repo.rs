//! Repository for connected agents.
//!
//! Identity flows from the authenticated key row — never from the wire —
//! so `upsert` is only ever called with key-derived values.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::error::SentinelError;

/// An agent as tracked by the hub.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AgentRow {
    pub agent_id: String,
    pub hostname: String,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

/// An agent with a computed online flag (for the dashboard).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AgentStatus {
    pub agent_id: String,
    pub hostname: String,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    /// Computed server-side: `last_seen_at` within `online_window_secs`.
    pub online: bool,
}

#[derive(Clone)]
pub struct AgentRepository {
    pool: PgPool,
}

impl AgentRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Creates or refreshes an agent's last-seen stamp. Identity values come
    /// from the authenticated key row.
    ///
    /// # Errors
    /// Database failure.
    pub async fn upsert_seen(&self, agent_id: &str, hostname: &str) -> Result<(), SentinelError> {
        sqlx::query(
            r"INSERT INTO agents (agent_id, hostname, first_seen_at, last_seen_at)
              VALUES ($1, $2, NOW(), NOW())
              ON CONFLICT (agent_id)
              DO UPDATE SET hostname = EXCLUDED.hostname, last_seen_at = NOW()",
        )
        .bind(agent_id)
        .bind(hostname)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Lists agents with an online flag: `last_seen_at` within
    /// `online_window_secs` (90s = 3 missed 30s metric cycles).
    ///
    /// # Errors
    /// Database failure.
    pub async fn list_with_status(
        &self,
        online_window_secs: i64,
    ) -> Result<Vec<AgentStatus>, SentinelError> {
        let rows = sqlx::query_as::<_, AgentStatus>(
            r"SELECT agent_id, hostname, first_seen_at, last_seen_at,
                     (last_seen_at > NOW() - make_interval(secs => $1)) AS online
              FROM agents
              ORDER BY hostname",
        )
        .bind(online_window_secs)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}

/// The online window used by the dashboard: 3 missed 30s cycles.
pub const ONLINE_WINDOW_SECS: i64 = 90;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn constructs_with_lazy_pool() {
        let pool = PgPool::connect_lazy("postgresql://test:test@localhost/none").unwrap();
        let _ = AgentRepository::new(pool);
    }
}
