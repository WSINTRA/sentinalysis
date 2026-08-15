//! In-memory [`LogDataSource`] for unit tests: no database required.
//!
//! Entry lists are stored newest-first, exactly like the database, so the
//! [`LogDataSource::newer`] cursor semantics match the Postgres query.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::SentinelError;
use crate::log_scanner::source::Source;
use crate::tui::data::{BoxFuture, DisplayLogEntry, LogDataSource, SourceInfo};

#[derive(Debug, Default)]
pub struct MemoryLogDataSource {
    vhosts: Vec<SourceInfo>,
    system_logs: Vec<SourceInfo>,
    /// Per-source entry lists, newest first (like the database).
    entries: HashMap<String, Vec<DisplayLogEntry>>,
}

impl MemoryLogDataSource {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_sources(mut self, vhosts: Vec<SourceInfo>, system_logs: Vec<SourceInfo>) -> Self {
        self.vhosts = vhosts;
        self.system_logs = system_logs;
        self
    }

    #[must_use]
    pub fn with_entries(mut self, name: &str, entries: Vec<DisplayLogEntry>) -> Self {
        self.entries.insert(name.to_string(), entries);
        self
    }
}

impl LogDataSource for MemoryLogDataSource {
    fn sources(&self) -> BoxFuture<'_, Result<Vec<SourceInfo>, SentinelError>> {
        let sources = [self.vhosts.clone(), self.system_logs.clone()].concat();
        Box::pin(async move { Ok(sources) })
    }

    fn recent(
        &self,
        source: &Source,
        limit: i64,
    ) -> BoxFuture<'_, Result<Vec<DisplayLogEntry>, SentinelError>> {
        let entries = self
            .entries
            .get(&source.name)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .collect::<Vec<_>>();
        Box::pin(async move { Ok(entries) })
    }

    fn newer(
        &self,
        source: &Source,
        since: DateTime<Utc>,
        since_id: Uuid,
        limit: i64,
    ) -> BoxFuture<'_, Result<Vec<DisplayLogEntry>, SentinelError>> {
        // Same rule as the Postgres row-value cursor: strictly newer
        // `(timestamp, id)`, and the list is already newest-first.
        let entries = self
            .entries
            .get(&source.name)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| (e.timestamp, e.id) > (since, since_id))
                    .take(usize::try_from(limit).unwrap_or(usize::MAX))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Box::pin(async move { Ok(entries) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_scanner::classifier::ThreatLevel;
    use crate::log_scanner::parser::LogLevel;

    fn entry(seq: u64, timestamp: DateTime<Utc>) -> DisplayLogEntry {
        DisplayLogEntry {
            id: Uuid::new_v4(),
            timestamp,
            level: LogLevel::Info,
            threat_level: ThreatLevel::None,
            message: format!("entry {seq}"),
            raw: String::new(),
            source_name: "test".to_string(),
            threat_categories: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_sources_returns_configured_lists() {
        let ds = MemoryLogDataSource::new().with_sources(
            vec![SourceInfo::new(
                crate::log_scanner::source::SourceKind::Vhost,
                "a.example.com",
                3,
            )],
            vec![SourceInfo::new(
                crate::log_scanner::source::SourceKind::SystemLog,
                "auth.log",
                0,
            )],
        );

        // Vhosts first, then system logs.
        let sources = ds.sources().await.unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].entry_count, 3);
        assert_eq!(
            sources[0].source.kind,
            crate::log_scanner::source::SourceKind::Vhost
        );
        assert_eq!(
            sources[1].source.kind,
            crate::log_scanner::source::SourceKind::SystemLog
        );
    }

    #[tokio::test]
    async fn test_recent_and_newer_cursor_semantics() {
        // Distinct, increasing timestamps (newest first, like the DB).
        let t0 = Utc::now();
        let at = |seq: u64| t0 + chrono::TimeDelta::try_seconds(seq.cast_signed()).unwrap();
        let ds = MemoryLogDataSource::new()
            .with_entries("s", vec![entry(3, at(3)), entry(2, at(2)), entry(1, at(1))]);
        let source = Source::vhost("s");

        let recent = ds.recent(&source, 10).await.unwrap();
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].message, "entry 3");

        // Cursor at the oldest on screen: only entries 1 and 2 are newer.
        let cursor = &recent[2];
        let newer = ds
            .newer(&source, cursor.timestamp, cursor.id, 10)
            .await
            .unwrap();
        assert_eq!(newer.len(), 2);
        assert_eq!(newer[0].message, "entry 3");
        assert_eq!(newer[1].message, "entry 2");

        // Unknown source: empty, no error.
        assert!(
            ds.newer(&Source::vhost("missing"), cursor.timestamp, cursor.id, 10)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
