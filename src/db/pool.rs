//! Database connection pool management.

use sqlx::PgPool;

use crate::error::SentinelError;

/// Create a connection pool for `database_url`.
pub async fn create_pool(database_url: &str) -> Result<PgPool, SentinelError> {
    let pool = PgPool::connect(database_url).await?;
    Ok(pool)
}

/// Verify the pool can run a trivial query.
pub async fn health_check(pool: &PgPool) -> Result<(), SentinelError> {
    sqlx::query("SELECT 1").fetch_one(pool).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bogus URL fails fast with a database error, no live server needed.
    #[tokio::test]
    async fn test_create_pool_invalid_url_fails() {
        let result = create_pool("postgresql://invalid:5432/nonexistent").await;
        assert!(matches!(result, Err(SentinelError::DatabaseError(_))));
    }
}
