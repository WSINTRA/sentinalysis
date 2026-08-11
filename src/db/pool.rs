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

    #[tokio::test]
    async fn test_create_pool_missing_env_fails() {
        unsafe {
            std::env::remove_var("DATABASE_URL");
        }
        let result = create_pool().await;
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
        unsafe {
            std::env::set_var("DATABASE_URL", "postgresql://invalid:5432/nonexistent");
        }
        let result = create_pool().await;
        assert!(result.is_err());
        match result {
            Err(SentinelError::DatabaseError(_)) => {}
            _ => panic!("Expected DatabaseError"),
        }
    }
}
