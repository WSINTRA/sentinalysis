//! `LogDataSource` backed by Postgres and filesystem source discovery.
//!
//! `PgLogDataSource` is the production data source: the source list comes
//! from [`SourceDiscovery`] (the configured watch targets on disk) and the
//! entry counts and entry lists come from [`LogQueryRepository`]. It also
//! owns the mapping from database rows to the display model.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

use crate::db::repositories::log_query_repo::{LogEntryRow, LogQueryRepository};
use crate::error::SentinelError;
use crate::log_scanner::classifier::ThreatLevel;
use crate::log_scanner::parser::LogLevel;
use crate::log_scanner::source::{Source, SourceKind};
use crate::log_scanner::source_discovery::SourceDiscovery;
use crate::tui::data::{BoxFuture, DisplayLogEntry, LogDataSource, SourceInfo};

/// The production data source: counts from the database, the source list
/// from filesystem discovery of the configured targets.
#[derive(Debug, Clone)]
pub struct PgLogDataSource {
    repo: LogQueryRepository,
    discovery: SourceDiscovery,
}

impl PgLogDataSource {
    #[must_use]
    pub fn new(pool: PgPool, discovery: SourceDiscovery) -> Self {
        Self {
            repo: LogQueryRepository::new(pool),
            discovery,
        }
    }
}
impl LogDataSource for PgLogDataSource {
    fn sources(&self) -> BoxFuture<'_, Result<Vec<SourceInfo>, SentinelError>> {
        // One discovery pass, split for the two count queries.
        let (vhosts, system_logs) = partition_by_kind(self.discovery.discover());

        Box::pin(async move {
            let vhost_infos = counts_for(&self.repo, SourceKind::Vhost, vhosts).await?;
            let system_infos = counts_for(&self.repo, SourceKind::SystemLog, system_logs).await?;
            Ok([vhost_infos, system_infos].concat())
        })
    }

    fn recent(
        &self,
        source: &Source,
        limit: i64,
    ) -> BoxFuture<'_, Result<Vec<DisplayLogEntry>, SentinelError>> {
        let source = source.clone();
        Box::pin(async move {
            let rows = self
                .repo
                .recent_entries(source.kind, &source.name, limit)
                .await?;
            Ok(rows.into_iter().map(row_to_display).collect())
        })
    }

    fn newer(
        &self,
        source: &Source,
        since: DateTime<Utc>,
        since_id: Uuid,
        limit: i64,
    ) -> BoxFuture<'_, Result<Vec<DisplayLogEntry>, SentinelError>> {
        let source = source.clone();
        Box::pin(async move {
            let rows = self
                .repo
                .newer_entries(source.kind, &source.name, since, since_id, limit)
                .await?;
            Ok(rows.into_iter().map(row_to_display).collect())
        })
    }
}

/// Split a discovered list into (vhosts, system logs), preserving order.
fn partition_by_kind(sources: Vec<Source>) -> (Vec<Source>, Vec<Source>) {
    let mut vhosts = Vec::new();
    let mut system_logs = Vec::new();
    for source in sources {
        match source.kind {
            SourceKind::Vhost => vhosts.push(source),
            SourceKind::SystemLog => system_logs.push(source),
        }
    }
    (vhosts, system_logs)
}

/// Entry counts for `sources`, as `SourceInfo` rows (zero when the
/// database has no entries yet). Skips the query for an empty list.
async fn counts_for(
    repo: &LogQueryRepository,
    kind: SourceKind,
    sources: Vec<Source>,
) -> Result<Vec<SourceInfo>, SentinelError> {
    if sources.is_empty() {
        return Ok(Vec::new());
    }

    let names: Vec<String> = sources.iter().map(|s| s.name.clone()).collect();
    let db_counts = repo.count_entries(kind, &names).await?;
    let counts: HashMap<String, i64> = db_counts.into_iter().collect();

    Ok(sources
        .into_iter()
        .map(|source| {
            SourceInfo::new(
                source.kind,
                source.name.clone(),
                usize::try_from(counts.get(&source.name).copied().unwrap_or(0)).unwrap_or(0),
            )
        })
        .collect())
}

/// Map a database row to the display model.
#[must_use]
pub fn row_to_display(row: LogEntryRow) -> DisplayLogEntry {
    DisplayLogEntry {
        id: row.id,
        timestamp: row.timestamp,
        level: LogLevel::from_db(&row.level),
        threat_level: ThreatLevel::from_db(&row.threat_level),
        message: row.message,
        raw: row.raw_line.unwrap_or_default(),
        source_name: row.source_name,
        threat_categories: row.threat_categories,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_row_to_display_maps_level_and_threat() {
        let row = LogEntryRow {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            level: "security".to_string(),
            message: "m".to_string(),
            raw_line: Some("raw".to_string()),
            source_name: "api.example.com".to_string(),
            threat_level: "critical".to_string(),
            threat_categories: vec!["command-injection".to_string()],
        };

        let display = row_to_display(row);
        assert_eq!(display.level, LogLevel::Security);
        assert_eq!(display.threat_level, ThreatLevel::Critical);
        assert_eq!(display.raw, "raw");
        assert_eq!(display.source_name, "api.example.com");
        assert_eq!(display.threat_categories, vec!["command-injection"]);
    }

    #[test]
    fn test_row_to_display_defaults_unknown_values() {
        let row = LogEntryRow {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            level: "weird-level".to_string(),
            message: "m".to_string(),
            raw_line: None,
            source_name: "s".to_string(),
            threat_level: "bogus".to_string(),
            threat_categories: Vec::new(),
        };

        let display = row_to_display(row);
        assert_eq!(display.level, LogLevel::Info);
        assert_eq!(display.threat_level, ThreatLevel::None);
        assert!(display.raw.is_empty());
    }
}
