//! Two-panel log viewer: a sources list (left) and an entry list (right).
//!
//! This module owns the viewer's state, action handling, and data loading
//! (all database access goes through [`LogQueryRepository`]); frame
//! drawing lives in the [`render`] submodule.

mod render;

use std::collections::HashMap;
use std::path::Path;

use ratatui::layout::Rect;
use ratatui::widgets::ListState;
use sqlx::PgPool;
use tracing::{error, info};

use crate::db::repositories::log_query_repo::{LogEntryRow, LogQueryRepository, LogSourceKind};
use crate::error::SentinelError;
use crate::log_scanner::classifier::ThreatLevel;
use crate::log_scanner::parser::LogLevel;
use crate::tui::action::Action;
use crate::tui::app::{DisplayLogEntry, VirtualHostInfo, VirtualHostSource};
use crate::tui::components::{BoxedFuture, Component};

/// Max entries kept in memory per host.
pub const MAX_ENTRIES_PER_HOST: usize = 1000;
/// Max entries fetched per poll for a single host.
const NEW_ENTRIES_PER_POLL: i64 = 100;
const NGINX_LOG_DIR: &str = "/var/log/nginx";
const AUTH_LOG_PATH: &str = "/var/log/auth.log";

/// Which panel receives navigation keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PanelFocus {
    HostList,
    LogList,
}

/// The kind of source the entry list currently shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectionType {
    VirtualHost,
    SystemLog,
}

pub struct LogViewer {
    repo: LogQueryRepository,
    virtual_hosts: Vec<VirtualHostInfo>,
    system_logs: Vec<VirtualHostInfo>,
    host_state: ListState,
    log_entries: HashMap<String, Vec<DisplayLogEntry>>,
    log_state: ListState,
    selected_host: Option<String>,
    selection_type: SelectionType,
    filter_mode: bool,
    filter_text: String,
    focus: PanelFocus,
}

impl LogViewer {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        let mut host_state = ListState::default();
        host_state.select(Some(0));

        let mut log_state = ListState::default();
        log_state.select(Some(0));

        Self {
            repo: LogQueryRepository::new(pool),
            virtual_hosts: Vec::new(),
            system_logs: Vec::new(),
            host_state,
            log_entries: HashMap::new(),
            log_state,
            selected_host: None,
            selection_type: SelectionType::VirtualHost,
            filter_mode: false,
            filter_text: String::new(),
            focus: PanelFocus::HostList,
        }
    }

    /// Discover vhosts from `<vhost>-access.log` files in the nginx log
    /// directory and load their entry counts.
    async fn load_virtual_hosts(&mut self) -> Result<(), SentinelError> {
        let log_dir = Path::new(NGINX_LOG_DIR);

        if !log_dir.exists() {
            self.virtual_hosts = vec![VirtualHostInfo {
                name: format!("Log directory not found: {NGINX_LOG_DIR}"),
                source: VirtualHostSource::LogEntry,
                entry_count: 0,
            }];
            return Ok(());
        }

        let entries = match std::fs::read_dir(log_dir) {
            Ok(entries) => entries,
            Err(e) => {
                error!("Failed to read log directory {}: {e}", log_dir.display());
                self.virtual_hosts = vec![VirtualHostInfo {
                    name: format!("Cannot read {NGINX_LOG_DIR}: {e}"),
                    source: VirtualHostSource::LogEntry,
                    entry_count: 0,
                }];
                return Ok(());
            }
        };

        let mut discovered_hosts = Vec::new();
        for entry in entries.filter_map(std::result::Result::ok) {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name.ends_with("-access.log") && !file_name.ends_with("-access.log.1") {
                let vhost_name = file_name.trim_end_matches("-access.log").to_string();
                discovered_hosts.push(vhost_name);
            }
        }

        discovered_hosts.sort();

        if discovered_hosts.is_empty() {
            self.virtual_hosts = vec![VirtualHostInfo {
                name: "No *-access.log files found".to_string(),
                source: VirtualHostSource::LogEntry,
                entry_count: 0,
            }];
            info!("No virtual hosts discovered from log files");
            return Ok(());
        }

        let hosts: Vec<String> = discovered_hosts.clone();
        let db_counts: Vec<(String, i64)> = self
            .repo
            .count_entries(LogSourceKind::Vhost, &hosts)
            .await?;
        let counts: HashMap<String, i64> = db_counts.into_iter().collect();

        self.virtual_hosts = discovered_hosts
            .into_iter()
            .map(|name| VirtualHostInfo {
                name: name.clone(),
                source: VirtualHostSource::LogEntry,
                entry_count: usize::try_from(counts.get(&name).copied().unwrap_or(0)).unwrap_or(0),
            })
            .collect();

        info!(
            "Loaded {} virtual hosts from log files",
            self.virtual_hosts.len()
        );

        self.load_system_logs().await?;
        Ok(())
    }

    /// Discover system logs (`access.log`, `auth.log`) and load their
    /// entry counts.
    async fn load_system_logs(&mut self) -> Result<(), SentinelError> {
        let mut system_log_names = Vec::new();

        let log_dir = Path::new(NGINX_LOG_DIR);
        if let Ok(entries) = std::fs::read_dir(log_dir) {
            for entry in entries.filter_map(std::result::Result::ok) {
                let file_name = entry.file_name().to_string_lossy().to_string();
                if file_name == "access.log" {
                    system_log_names.push(file_name);
                }
            }
        }

        if Path::new(AUTH_LOG_PATH).exists() {
            system_log_names.push("auth.log".to_string());
        }

        system_log_names.sort();

        if system_log_names.is_empty() {
            self.system_logs = Vec::new();
            return Ok(());
        }

        let names: Vec<String> = system_log_names.clone();
        let db_counts: Vec<(String, i64)> = self
            .repo
            .count_entries(LogSourceKind::SystemLog, &names)
            .await?;
        let counts: HashMap<String, i64> = db_counts.into_iter().collect();

        self.system_logs = system_log_names
            .into_iter()
            .map(|name| VirtualHostInfo {
                name: name.clone(),
                source: VirtualHostSource::SystemdService,
                entry_count: usize::try_from(counts.get(&name).copied().unwrap_or(0)).unwrap_or(0),
            })
            .collect();

        info!("Loaded {} system logs", self.system_logs.len());
        Ok(())
    }

    /// Load the most recent entries for `name` using the current selection
    /// type, replacing whatever was cached for it.
    async fn load_recent_entries(&mut self, name: &str) -> Result<(), SentinelError> {
        let kind = self.source_kind();
        let limit = i64::try_from(MAX_ENTRIES_PER_HOST).unwrap_or(i64::MAX);

        let rows = self.repo.recent_entries(kind, name, limit).await?;
        let entries: Vec<DisplayLogEntry> = rows.into_iter().map(Self::row_to_display).collect();

        info!("Loaded {} entries for '{name}'", entries.len());
        self.log_entries.insert(name.to_string(), entries);
        self.log_state.select(Some(0));
        Ok(())
    }

    /// Map a database row to the display model.
    #[must_use]
    pub fn row_to_display(row: LogEntryRow) -> DisplayLogEntry {
        let level = LogLevel::from_db(&row.level);

        DisplayLogEntry {
            id: row.id,
            timestamp: row.timestamp,
            level,
            threat_level: ThreatLevel::from_db(&row.threat_level),
            message: row.message,
            raw: row.raw_line.unwrap_or_default(),
            virtual_host: row.source_name,
            threat_categories: row.threat_categories,
        }
    }

    /// The repository source kind for the current selection.
    fn source_kind(&self) -> LogSourceKind {
        match self.selection_type {
            SelectionType::SystemLog => LogSourceKind::SystemLog,
            SelectionType::VirtualHost => LogSourceKind::Vhost,
        }
    }

    /// Poll the database for entries newer than the oldest one on screen
    /// and prepend them to the cached list for `name`.
    async fn check_new_entries(
        &mut self,
        name: &str,
        selection_type: SelectionType,
    ) -> Result<(), SentinelError> {
        // Entries are stored newest-first, so the last one is the oldest on
        // screen; everything newer than it is still missing.
        let Some((since, since_id)) = self
            .log_entries
            .get(name)
            .and_then(|entries| entries.last())
            .map(|oldest| (oldest.timestamp, oldest.id))
        else {
            return Ok(());
        };

        let kind = match selection_type {
            SelectionType::SystemLog => LogSourceKind::SystemLog,
            SelectionType::VirtualHost => LogSourceKind::Vhost,
        };

        let new_rows = self
            .repo
            .newer_entries(kind, name, since, since_id, NEW_ENTRIES_PER_POLL)
            .await?;

        if new_rows.is_empty() {
            return Ok(());
        }

        let new_entries: Vec<DisplayLogEntry> =
            new_rows.into_iter().map(Self::row_to_display).collect();

        if let Some(host_entries) = self.log_entries.get_mut(name) {
            host_entries.splice(0..0, new_entries);
            if host_entries.len() > MAX_ENTRIES_PER_HOST {
                host_entries.truncate(MAX_ENTRIES_PER_HOST);
            }
        }

        Ok(())
    }

    /// Total number of rows in the sources panel, including section headers.
    fn total_host_list_len(&self) -> usize {
        let mut len = 1 + self.virtual_hosts.len();
        if !self.system_logs.is_empty() {
            len += 1 + self.system_logs.len();
        }
        len
    }

    /// What source (if any) the sources-panel row at `index` points at.
    /// Header rows (`Virtual Hosts`, `System Logs`) map to `None`.
    fn resolve_selection(&self, index: usize) -> Option<(String, SelectionType)> {
        // Row 0 is the "Virtual Hosts" header.
        if index == 0 {
            return None;
        }
        if let Some(vhost) = self.virtual_hosts.get(index - 1) {
            return Some((vhost.name.clone(), SelectionType::VirtualHost));
        }

        // Next row is the "System Logs" header, then the system logs.
        let system_header = 1 + self.virtual_hosts.len();
        if !self.system_logs.is_empty()
            && index > system_header
            && let Some(system_log) = self.system_logs.get(index - system_header - 1)
        {
            return Some((system_log.name.clone(), SelectionType::SystemLog));
        }

        None
    }

    /// Highest valid index of the selected host's entry list (0 when empty).
    fn log_list_max(&self) -> usize {
        self.selected_host
            .as_ref()
            .and_then(|h| self.log_entries.get(h).map(|v| v.len().saturating_sub(1)))
            .unwrap_or(0)
    }

    /// Route actions while the filter box is active: keys edit the filter
    /// text, Esc clears it, and everything else is swallowed. Returns the
    /// next action to propagate (only `Quit` passes through).
    fn handle_filter_action(&mut self, action: &Action) -> Option<Action> {
        match action {
            Action::FilterInput(c) => {
                self.filter_text.push(*c);
                None
            }
            Action::FilterBackspace => {
                self.filter_text.pop();
                None
            }
            Action::ClearFilter => {
                self.filter_mode = false;
                self.filter_text.clear();
                None
            }
            // Toggling or refreshing exits filter mode without a text change.
            Action::ToggleFilter | Action::Refresh => {
                self.filter_mode = false;
                None
            }
            Action::Quit => Some(Action::Quit),
            _ => None,
        }
    }

    /// Move the selection of the focused panel by `delta` positions,
    /// clamped to the panel bounds.
    fn move_selection(&mut self, delta: isize) {
        match self.focus {
            PanelFocus::HostList => {
                if let Some(i) = self.host_state.selected() {
                    let max = self.total_host_list_len().saturating_sub(1);
                    self.host_state
                        .select(Some(i.saturating_add_signed(delta).min(max)));
                }
            }
            PanelFocus::LogList => {
                if let Some(i) = self.log_state.selected() {
                    self.log_state.select(Some(
                        i.saturating_add_signed(delta).min(self.log_list_max()),
                    ));
                }
            }
        }
    }
}

impl Component for LogViewer {
    fn init(&mut self) -> BoxedFuture<'_, Result<(), SentinelError>> {
        Box::pin(async move {
            self.load_virtual_hosts().await?;

            if let Some(first_host) = self.virtual_hosts.first().map(|h| h.name.clone()) {
                self.selected_host = Some(first_host.clone());
                self.load_recent_entries(&first_host).await?;
            }

            Ok(())
        })
    }

    fn handle_action<'a>(
        &'a mut self,
        action: &'a Action,
    ) -> BoxedFuture<'a, Result<Option<Action>, SentinelError>> {
        Box::pin(async move {
            if self.filter_mode {
                return Ok(self.handle_filter_action(action));
            }

            match action {
                Action::Quit => Ok(Some(Action::Quit)),
                Action::ToggleFocus => {
                    self.focus = match self.focus {
                        PanelFocus::HostList => PanelFocus::LogList,
                        PanelFocus::LogList => PanelFocus::HostList,
                    };
                    Ok(None)
                }
                Action::SelectUp => {
                    self.move_selection(-1);
                    Ok(None)
                }
                Action::SelectDown => {
                    self.move_selection(1);
                    Ok(None)
                }
                Action::Refresh => {
                    if let Some(selected) = self.host_state.selected()
                        && let Some((name, selection_type)) = self.resolve_selection(selected)
                        && self.selected_host.as_ref() != Some(&name)
                    {
                        self.selected_host = Some(name.clone());
                        self.selection_type = selection_type;
                        self.log_state.select(Some(0));
                        if let Err(e) = self.load_recent_entries(&name).await {
                            error!("failed to load entries for '{name}': {e}");
                        }
                    }
                    Ok(None)
                }
                Action::ToggleFilter => {
                    self.filter_mode = true;
                    Ok(None)
                }
                Action::ClearFilter => {
                    self.filter_text.clear();
                    Ok(None)
                }
                Action::PageUp => {
                    if let Some(i) = self.log_state.selected() {
                        self.log_state.select(Some(i.saturating_sub(20)));
                    }
                    Ok(None)
                }
                Action::PageDown => {
                    if let Some(i) = self.log_state.selected() {
                        self.log_state
                            .select(Some((i + 20).min(self.log_list_max())));
                    }
                    Ok(None)
                }
                Action::ScrollToTop => {
                    self.log_state.select(Some(0));
                    Ok(None)
                }
                Action::ScrollToBottom => {
                    // `log_list_max` reports 0 for an empty list, matching the
                    // previous behaviour of selecting index 0 in that case.
                    if self
                        .selected_host
                        .as_ref()
                        .is_some_and(|h| self.log_entries.contains_key(h))
                    {
                        self.log_state.select(Some(self.log_list_max()));
                    }
                    Ok(None)
                }
                Action::Tick => {
                    if let Some(ref selected) = self.selected_host {
                        let st = self.selection_type;
                        let name = selected.clone();
                        let _ = self.check_new_entries(&name, st).await;
                    }
                    Ok(None)
                }
                _ => Ok(None),
            }
        })
    }

    fn draw(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        self.render(frame, area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    /// `connect_lazy` performs no I/O, so tests need no database.
    fn viewer() -> LogViewer {
        let pool = PgPool::connect_lazy("postgresql://localhost/sentinel")
            .expect("lazy pool does not connect");
        LogViewer::new(pool)
    }

    fn host(name: &str) -> VirtualHostInfo {
        VirtualHostInfo {
            name: name.to_string(),
            source: VirtualHostSource::LogEntry,
            entry_count: 0,
        }
    }

    fn display_entry(seq: u64) -> DisplayLogEntry {
        DisplayLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            level: LogLevel::Info,
            threat_level: ThreatLevel::None,
            message: format!("entry {seq}"),
            raw: String::new(),
            virtual_host: "test".to_string(),
            threat_categories: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_resolve_selection_skips_headers() {
        let mut v = viewer();
        v.virtual_hosts = vec![host("api.example.com"), host("shop.example.com")];
        v.system_logs = vec![host("auth.log")];

        // 0 = "Virtual Hosts" header.
        assert_eq!(v.resolve_selection(0), None);
        assert_eq!(
            v.resolve_selection(1),
            Some(("api.example.com".to_string(), SelectionType::VirtualHost))
        );
        assert_eq!(
            v.resolve_selection(2),
            Some(("shop.example.com".to_string(), SelectionType::VirtualHost))
        );
        // 3 = "System Logs" header.
        assert_eq!(v.resolve_selection(3), None);
        assert_eq!(
            v.resolve_selection(4),
            Some(("auth.log".to_string(), SelectionType::SystemLog))
        );
        assert_eq!(v.resolve_selection(5), None);
    }

    #[tokio::test]
    async fn test_resolve_selection_without_system_logs() {
        let mut v = viewer();
        v.virtual_hosts = vec![host("only.example.com")];

        assert_eq!(
            v.resolve_selection(1),
            Some(("only.example.com".to_string(), SelectionType::VirtualHost))
        );
        // No system-log section at all.
        assert_eq!(v.resolve_selection(2), None);
    }

    #[tokio::test]
    async fn test_move_selection_clamps_to_bounds() {
        let mut v = viewer();
        v.virtual_hosts = vec![host("a"), host("b")];

        v.focus = PanelFocus::HostList;
        v.host_state.select(Some(0));
        v.move_selection(-1);
        assert_eq!(v.host_state.selected(), Some(0), "cannot go below 0");

        v.move_selection(100);
        assert_eq!(
            v.host_state.selected(),
            Some(v.total_host_list_len() - 1),
            "cannot go past the last row"
        );
    }

    #[tokio::test]
    async fn test_filter_action_edits_and_exits() {
        let mut v = viewer();
        v.filter_mode = true;

        for c in ['a', 'b', 'c'] {
            let action = Action::FilterInput(c);
            assert_eq!(v.handle_filter_action(&action), None);
        }
        assert_eq!(v.filter_text, "abc");

        let action = Action::FilterBackspace;
        assert_eq!(v.handle_filter_action(&action), None);
        assert_eq!(v.filter_text, "ab");

        assert_eq!(v.handle_filter_action(&Action::Quit), Some(Action::Quit));

        let action = Action::ClearFilter;
        assert_eq!(v.handle_filter_action(&action), None);
        assert!(!v.filter_mode, "Esc exits filter mode");
        assert!(v.filter_text.is_empty());
    }

    #[tokio::test]
    async fn test_filter_action_swallowss_navigation() {
        let mut v = viewer();
        v.filter_mode = true;
        v.focus = PanelFocus::HostList;
        v.host_state.select(Some(0));

        // Navigation keys are swallowed while typing a filter.
        assert_eq!(v.handle_filter_action(&Action::SelectDown), None);
        assert_eq!(v.host_state.selected(), Some(0));
    }

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

        let display = LogViewer::row_to_display(row);
        assert_eq!(display.level, LogLevel::Security);
        assert_eq!(display.threat_level, ThreatLevel::Critical);
        assert_eq!(display.raw, "raw");
        assert_eq!(display.virtual_host, "api.example.com");
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

        let display = LogViewer::row_to_display(row);
        assert_eq!(display.level, LogLevel::Info);
        assert_eq!(display.threat_level, ThreatLevel::None);
        assert!(display.raw.is_empty());
    }

    #[tokio::test]
    async fn test_log_list_max_empty_and_full() {
        let mut v = viewer();
        v.selected_host = Some("h".to_string());
        assert_eq!(v.log_list_max(), 0, "no entries yet");

        v.log_entries
            .insert("h".to_string(), vec![display_entry(0), display_entry(1)]);
        assert_eq!(v.log_list_max(), 1);
    }
}
