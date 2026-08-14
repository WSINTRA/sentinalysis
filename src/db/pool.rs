use sqlx::PgPool;
use std::env;

use crate::error::SentinelError;

pub async fn create_pool() -> Result<PgPool, SentinelError> {
    let database_url = env::var("DATABASE_URL").map_err(|_| {
        SentinelError::ConfigError("DATABASE_URL environment variable not set".into())
    })?;

    PgPool::connect(&database_url)
        .await
        .map_err(|e| SentinelError::DatabaseError(e.to_string()))
}

pub async fn health_check(pool: &PgPool) -> Result<(), SentinelError> {
    sqlx::query("SELECT 1")
        .fetch_one(pool)
        .await
        .map(|_| ())
        .map_err(|e| SentinelError::DatabaseError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises tests that mutate the process environment, since env vars
    /// are process-global. A tokio mutex is used so the guard can be held
    /// across the `create_pool` await without blocking the runtime.
    static ENV_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

    async fn lock_env() -> tokio::sync::MutexGuard<'static, ()> {
        ENV_LOCK.get_or_init(Default::default).lock().await
    }

    fn set_database_url(value: Option<&str>) -> Option<String> {
        let original = std::env::var("DATABASE_URL").ok();
        match value {
            Some(url) => unsafe { std::env::set_var("DATABASE_URL", url) },
            None => unsafe { std::env::remove_var("DATABASE_URL") },
        }
        original
    }

    #[tokio::test]
    async fn test_create_pool_missing_env_fails() {
        let _guard = lock_env().await;
        let original = set_database_url(None);
        let result = create_pool().await;
        set_database_url(original.as_deref());
        assert!(result.is_err());
        match result {
            Err(SentinelError::ConfigError(msg)) => {
                assert!(msg.contains("DATABASE_URL"));
            }
            _ => panic!("Expected ConfigError"),
        }
    }

    #[tokio::test]
    async fn test_create_pool_invalid_url_fails() {
        let _guard = lock_env().await;
        let original = set_database_url(Some("postgresql://invalid:5432/nonexistent"));
        let result = create_pool().await;
        set_database_url(original.as_deref());
        assert!(result.is_err());
        match result {
            Err(SentinelError::DatabaseError(_)) => {}
            _ => panic!("Expected DatabaseError"),
        }
    }
}
