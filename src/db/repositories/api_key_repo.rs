//! Repository for hub API keys.
//!
//! The `api_keys` row is the single source of truth for identity and
//! permissions: an agent key carries the trusted `agent_id`/`hostname`, an
//! app key carries `app_name`, and a dashboard key carries neither. Lookup
//! goes through the indexed, public `key_id` column so authentication
//! costs one indexed read plus one argon2 verify — never a scan.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::SentinelError;

/// Full key row as stored (never exposes the raw secret — only its
/// argon2 `hash`).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ApiKeyRow {
    pub id: Uuid,
    pub name: String,
    pub hash: String,
    pub permissions: Vec<String>,
    pub key_id: String,
    pub agent_id: Option<String>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ApiKeyRow {
    /// The key's role, derived from its identity binding.
    ///
    /// The Postgres `chk_api_key_role` constraint guarantees at most one of
    /// `agent_id`/`app_name` is set.
    #[must_use]
    pub fn role(&self) -> KeyRole {
        if self.agent_id.is_some() {
            KeyRole::Agent
        } else if self.app_name.is_some() {
            KeyRole::App
        } else {
            KeyRole::Dashboard
        }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// The three key roles a hub key can have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    /// Bounded to one agent; may ingest metrics + logs for that agent.
    Agent,
    /// Bounded to one app; may ingest events under that app's name.
    App,
    /// Read-only dashboard access.
    Dashboard,
}

/// Values for a new key. The caller (CLI) computes the `key_id`, the
/// argon2 `hash`, and the identity binding; the secret is never persisted.
#[derive(Debug, Clone)]
pub struct InsertApiKey {
    pub name: String,
    pub hash: String,
    pub permissions: Vec<String>,
    pub key_id: String,
    pub agent_id: Option<String>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
}

#[derive(Clone)]
pub struct ApiKeyRepository {
    pool: PgPool,
}

impl ApiKeyRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Creates a key. Enforces the one-role binding in Rust (mirroring the
    /// Postgres `CHECK`) so a caller bug fails with a clear message.
    ///
    /// # Errors
    /// Database failure, or a role binding that is not exactly one of
    /// agent / app / dashboard.
    pub async fn create(&self, key: &InsertApiKey) -> Result<ApiKeyRow, SentinelError> {
        let role_valid = (key.agent_id.is_some() && key.app_name.is_none())
            || (key.agent_id.is_none() && key.app_name.is_some())
            || (key.agent_id.is_none() && key.app_name.is_none());
        if !role_valid {
            return Err(SentinelError::AuthError(
                "API key must bind at most one of agent_id or app_name".into(),
            ));
        }

        let row = sqlx::query_as::<_, ApiKeyRow>(
            r"INSERT INTO api_keys (name, hash, permissions, key_id, agent_id, hostname, app_name)
              VALUES ($1, $2, $3, $4, $5, $6, $7)
              RETURNING id, name, hash, permissions, key_id, agent_id, hostname, app_name,
                        created_at, last_used_at, revoked_at",
        )
        .bind(&key.name)
        .bind(&key.hash)
        .bind(&key.permissions)
        .bind(&key.key_id)
        .bind(key.agent_id.as_deref())
        .bind(key.hostname.as_deref())
        .bind(key.app_name.as_deref())
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    /// Fetches the active (non-revoked) key for a `key_id`.
    ///
    /// # Errors
    /// Database failure.
    pub async fn find_active_by_key_id(
        &self,
        key_id: &str,
    ) -> Result<Option<ApiKeyRow>, SentinelError> {
        let row = sqlx::query_as::<_, ApiKeyRow>(
            r"SELECT id, name, hash, permissions, key_id, agent_id, hostname, app_name,
                      created_at, last_used_at, revoked_at
               FROM api_keys
               WHERE key_id = $1 AND revoked_at IS NULL",
        )
        .bind(key_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Updates `last_used_at` for a key.
    ///
    /// # Errors
    /// Database failure.
    pub async fn touch_last_used(&self, id: Uuid) -> Result<(), SentinelError> {
        sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Revokes a key. Returns `false` if it was already revoked or unknown.
    ///
    /// # Errors
    /// Database failure.
    pub async fn revoke(&self, key_id: &str) -> Result<bool, SentinelError> {
        let result = sqlx::query(
            "UPDATE api_keys SET revoked_at = NOW() WHERE key_id = $1 AND revoked_at IS NULL",
        )
        .bind(key_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Lists keys for management purposes. Never returns the hash.
    ///
    /// # Errors
    /// Database failure.
    pub async fn list(&self) -> Result<Vec<ApiKeySummary>, SentinelError> {
        let rows = sqlx::query_as::<_, ApiKeySummary>(
            r"SELECT key_id, name, agent_id, hostname, app_name, permissions,
                      created_at, last_used_at, revoked_at
               FROM api_keys ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}

/// Management view of a key: metadata only, no secret material.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ApiKeySummary {
    pub key_id: String,
    pub name: String,
    pub agent_id: Option<String>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub permissions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ApiKeySummary {
    #[must_use]
    pub fn role(&self) -> KeyRole {
        if self.agent_id.is_some() {
            KeyRole::Agent
        } else if self.app_name.is_some() {
            KeyRole::App
        } else {
            KeyRole::Dashboard
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_from_row_bindings() {
        let base = ApiKeyRow {
            id: Uuid::new_v4(),
            name: "test".into(),
            hash: "hash".into(),
            permissions: vec![],
            key_id: "a1b2c3d4".into(),
            agent_id: None,
            hostname: None,
            app_name: None,
            created_at: Utc::now(),
            last_used_at: None,
            revoked_at: None,
        };

        let mut agent = base.clone();
        agent.agent_id = Some("ecom-01".into());
        agent.hostname = Some("ecom-vps".into());
        assert_eq!(agent.role(), KeyRole::Agent);

        let mut app = base.clone();
        app.app_name = Some("globalware".into());
        assert_eq!(app.role(), KeyRole::App);

        assert_eq!(base.role(), KeyRole::Dashboard);
        assert!(base.is_active());

        let mut revoked = base.clone();
        revoked.revoked_at = Some(Utc::now());
        assert!(!revoked.is_active());
    }
}
