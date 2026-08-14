use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::db::models::{InsertService, Service};
use crate::error::SentinelError;

#[derive(Clone)]
pub struct ServiceRepository {
    pool: PgPool,
}

impl ServiceRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, service: &InsertService) -> Result<Uuid, SentinelError> {
        let result = sqlx::query(
            r"INSERT INTO services (name, unit_type, log_paths, virtual_host) VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(&service.name)
        .bind(&service.unit_type)
        .bind(service.log_paths.as_deref())
        .bind(service.virtual_host.as_deref())
        .fetch_one(&self.pool)
        .await?;

        Ok(result.get::<Uuid, _>("id"))
    }

    pub async fn find_by_name(&self, name: &str) -> Result<Option<Service>, SentinelError> {
        let service = sqlx::query_as::<_, Service>(
            r"SELECT id, name, unit_type, log_paths, virtual_host, created_at FROM services WHERE name = $1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(service)
    }

    pub async fn find_by_virtual_host(
        &self,
        vhost: &str,
    ) -> Result<Option<Service>, SentinelError> {
        let service = sqlx::query_as::<_, Service>(
            r"SELECT id, name, unit_type, log_paths, virtual_host, created_at FROM services WHERE virtual_host = $1",
        )
        .bind(vhost)
        .fetch_optional(&self.pool)
        .await?;
        Ok(service)
    }

    pub async fn get_or_create(&self, service: &InsertService) -> Result<Uuid, SentinelError> {
        if let Some(existing) = self.find_by_name(&service.name).await? {
            return Ok(existing.id);
        }
        self.create(service).await
    }

    pub async fn list_all(&self) -> Result<Vec<Service>, SentinelError> {
        let services = sqlx::query_as::<_, Service>(
            r"SELECT id, name, unit_type, log_paths, virtual_host, created_at FROM services ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(services)
    }

    pub async fn delete(&self, id: Uuid) -> Result<bool, SentinelError> {
        let result = sqlx::query("DELETE FROM services WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_repository_creation() {
        let pool = PgPool::connect_lazy("postgresql://test:test@localhost/test").unwrap();
        let repo = ServiceRepository::new(pool);
        let _ = &repo;
    }

    #[test]
    fn test_insert_service_with_vhost() {
        let service = InsertService {
            name: "api.example.com".to_string(),
            unit_type: "nginx-vhost".to_string(),
            log_paths: Some(vec![
                "/var/log/nginx/api.example.com-access.log".to_string(),
            ]),
            virtual_host: Some("api.example.com".to_string()),
        };
        assert_eq!(service.name, "api.example.com");
        assert_eq!(service.virtual_host, Some("api.example.com".to_string()));
    }

    #[test]
    fn test_insert_service_systemd() {
        let service = InsertService {
            name: "my-python-app".to_string(),
            unit_type: "systemd-service".to_string(),
            log_paths: None,
            virtual_host: None,
        };
        assert_eq!(service.unit_type, "systemd-service");
        assert!(service.log_paths.is_none());
    }
}
