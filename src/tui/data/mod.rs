//! TUI data layer: the view models the log viewer renders plus the
//! [`LogDataSource`] trait that supplies them.
//!
//! [`DisplayLogEntry`] is one row of the entry list; [`SourceInfo`] is
//! one row of the sources panel (a discovered [`Source`] plus its entry
//! count). The production implementation is [`pg::PgLogDataSource`]
//! (Postgres + filesystem discovery); unit tests use
//! [`memory::MemoryLogDataSource`]. Components depend only on the trait,
//! so the viewer is testable without a database.

pub mod memory;
pub mod pg;

use std::future::Future;
use std::pin::Pin;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::SentinelError;
use crate::log_scanner::classifier::ThreatLevel;
use crate::log_scanner::parser::LogLevel;
use crate::log_scanner::source::{Source, SourceKind};

/// One log entry as shown in the entry list.
#[derive(Debug, Clone)]
pub struct DisplayLogEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub threat_level: ThreatLevel,
    pub message: String,
    pub raw: String,
    pub source_name: String,
    pub threat_categories: Vec<String>,
}

/// A row in the sources panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceInfo {
    pub source: Source,
    pub entry_count: usize,
}

impl SourceInfo {
    #[must_use]
    pub fn new(kind: SourceKind, name: impl Into<String>, entry_count: usize) -> Self {
        let source = match kind {
            SourceKind::Vhost => Source::vhost(name),
            SourceKind::SystemLog => Source::system_log(name),
        };
        Self {
            source,
            entry_count,
        }
    }
}

/// Supplies the data the log viewer renders: the sources panel (with
/// entry counts) and the per-source entry lists.
///
/// Implementations decide where the data comes from (Postgres in
/// production, memory in tests). All methods are async so a
/// implementation can perform I/O without blocking the runtime.
pub trait LogDataSource: Send {
    /// The sources panel rows, each with its entry count. Vhosts come
    /// first, then system logs (each group sorted by name), so callers
    /// can split the list on [`SourceKind`].
    fn sources(&self) -> BoxFuture<'_, Result<Vec<SourceInfo>, SentinelError>>;

    /// The most recent `limit` entries for `source`, newest first.
    fn recent(
        &self,
        source: &Source,
        limit: i64,
    ) -> BoxFuture<'_, Result<Vec<DisplayLogEntry>, SentinelError>>;

    /// Entries strictly newer than the `(since, since_id)` cursor, newest
    /// first, up to `limit`. The cursor is the `(timestamp, id)` of the
    /// oldest entry already on screen, so entries sharing a timestamp are
    /// neither missed nor duplicated.
    fn newer(
        &self,
        source: &Source,
        since: DateTime<Utc>,
        since_id: Uuid,
        limit: i64,
    ) -> BoxFuture<'_, Result<Vec<DisplayLogEntry>, SentinelError>>;
}

/// A boxed, send, lifetime-bound future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
