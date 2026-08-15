//! TUI view models: what the log viewer shows on screen.
//!
//! [`DisplayLogEntry`] is one row of the entry list; [`SourceInfo`] is
//! one row of the sources panel (a discovered [`Source`] plus its entry
//! count). Data-source implementations (see the `LogDataSource` trait
//! in this module) produce these models; components only render them.

use chrono::{DateTime, Utc};
use uuid::Uuid;

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
