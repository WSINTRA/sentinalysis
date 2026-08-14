//! Row models mirroring the Postgres schema.
//!
//! `*` structs with `FromRow` are read models; `Insert*` structs are the
//! write side. `SystemMetric`, `ActiveSession`, `Alert`, and `ApiKey`
//! mirror tables that exist in the schema but no code path uses yet.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Service {
    pub id: Uuid,
    pub name: String,
    pub unit_type: String,
    pub log_paths: Option<Vec<String>>,
    pub virtual_host: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: Uuid,
    pub service_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
    pub raw_line: Option<String>,
    pub client_ip: Option<String>,
    pub request_path: Option<String>,
    pub status_code: Option<i16>,
    pub response_time_ms: Option<i64>,
    pub is_noise: bool,
    pub noise_reason: Option<String>,
    pub threat_level: String,
    pub threat_categories: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SystemMetric {
    pub id: Uuid,
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

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ActiveSession {
    pub id: Uuid,
    pub user: String,
    pub terminal: String,
    pub source_ip: Option<String>,
    pub login_time: DateTime<Utc>,
    pub idle_seconds: i64,
    pub pid: Option<i32>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub service_id: Option<Uuid>,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub resolved: bool,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub name: String,
    pub hash: String,
    pub permissions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InsertLogEntry {
    pub service_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
    pub raw_line: Option<String>,
    pub client_ip: Option<String>,
    pub request_path: Option<String>,
    pub status_code: Option<i16>,
    pub response_time_ms: Option<i64>,
    pub is_noise: bool,
    pub noise_reason: Option<String>,
    /// Stored threat level (see `ThreatLevel::as_str`); `'none'` when clean.
    pub threat_level: String,
    /// Stored threat categories (see `ThreatCategory::as_str`).
    pub threat_categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InsertService {
    pub name: String,
    pub unit_type: String,
    pub log_paths: Option<Vec<String>>,
    pub virtual_host: Option<String>,
}
