use std::collections::HashMap;
use std::path::Path;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use sqlx::PgPool;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, info};

use crate::db::repositories::log_query_repo::{LogEntryRow, LogQueryRepository, LogSourceKind};
use crate::error::SentinelError;
use crate::log_scanner::classifier::ThreatLevel;
use crate::log_scanner::parser::LogLevel;
use crate::tui::action::Action;
use crate::tui::app::{DisplayLogEntry, VirtualHostInfo, VirtualHostSource};
use crate::tui::components::{BoxedFuture, Component};

const MAX_ENTRIES_PER_HOST: usize = 1000;
/// Max entries fetched per poll for a single host.
const NEW_ENTRIES_PER_POLL: i64 = 100;
const NGINX_LOG_DIR: &str = "/var/log/nginx";

#[derive(Debug, Clone, Copy, PartialEq)]
enum PanelFocus {
    HostList,
    LogList,
}

pub struct LogViewer {
    repo: LogQueryRepository,
    _entry_tx: UnboundedSender<DisplayLogEntry>,
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

#[derive(Debug, Clone, Copy, PartialEq)]
enum SelectionType {
    VirtualHost,
    SystemLog,
}

impl LogViewer {
    #[must_use]
    pub fn new(pool: PgPool, entry_tx: UnboundedSender<DisplayLogEntry>) -> Self {
        let mut host_state = ListState::default();
        host_state.select(Some(0));

        let mut log_state = ListState::default();
        log_state.select(Some(0));

        Self {
            repo: LogQueryRepository::new(pool),
            _entry_tx: entry_tx,
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

        let mut discovered_hosts = Vec::new();

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

        if Path::new("/var/log/auth.log").exists() {
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

    fn row_to_display(row: LogEntryRow) -> DisplayLogEntry {
        let level = match row.level.as_str() {
            "debug" => LogLevel::Debug,
            "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            "critical" => LogLevel::Critical,
            "security" => LogLevel::Security,
            _ => LogLevel::Info,
        };

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

    fn get_level_style(level: LogLevel, threat: ThreatLevel) -> Style {
        let base_color = match level {
            LogLevel::Debug => Color::DarkGray,
            LogLevel::Info => Color::White,
            LogLevel::Warn => Color::Yellow,
            LogLevel::Error => Color::Red,
            LogLevel::Critical | LogLevel::Security => Color::Magenta,
        };

        let modifier = if threat >= ThreatLevel::High {
            Modifier::BOLD | Modifier::REVERSED
        } else {
            Modifier::empty()
        };

        Style::new().fg(base_color).add_modifier(modifier)
    }

    fn entry_to_list_item(entry: &DisplayLogEntry) -> ListItem<'_> {
        let timestamp = entry.timestamp.format("%H:%M:%S").to_string();
        let level_str = match entry.level {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Critical => "CRITICAL",
            LogLevel::Security => "SECURITY",
        };

        let threat_badge = if entry.threat_categories.is_empty() {
            String::new()
        } else {
            format!(" [{}]", entry.threat_categories.join(","))
        };

        let line = Line::from(vec![
            Span::styled(format!("[{timestamp}] "), Style::new().fg(Color::DarkGray)),
            Span::styled(
                format!("[{level_str}] "),
                Self::get_level_style(entry.level, entry.threat_level),
            ),
            Span::raw(entry.message.clone()),
            Span::styled(
                threat_badge,
                Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD),
            ),
        ]);

        ListItem::new(line)
    }

    fn render_host_list(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        let mut items: Vec<ListItem> = Vec::new();

        items.push(ListItem::new(
            Line::raw("Virtual Hosts").style(Style::new().add_modifier(Modifier::BOLD)),
        ));
        for h in &self.virtual_hosts {
            items.push(ListItem::new(Line::raw(format!("[L] {}", h.name))));
        }

        if !self.system_logs.is_empty() {
            items.push(ListItem::new(
                Line::raw("System Logs").style(Style::new().add_modifier(Modifier::BOLD)),
            ));
            for h in &self.system_logs {
                items.push(ListItem::new(Line::raw(format!("[S] {}", h.name))));
            }
        }

        let focused = self.focus == PanelFocus::HostList;
        let border_style = if focused {
            Style::new().fg(Color::Cyan)
        } else {
            Style::new().fg(Color::DarkGray)
        };

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Sources")
                    .border_style(border_style),
            )
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED));

        frame.render_stateful_widget(list, area, &mut self.host_state);
    }

    fn render_log_list(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        let title = self.selected_host.as_deref().unwrap_or("No host selected");

        let entries = self
            .selected_host
            .as_ref()
            .and_then(|h| self.log_entries.get(h).map(Vec::as_slice))
            .unwrap_or(&[]);

        let filtered: Vec<&DisplayLogEntry> = if self.filter_text.is_empty() {
            entries.iter().collect()
        } else {
            let filter_lower = self.filter_text.to_lowercase();
            entries
                .iter()
                .filter(|e| {
                    e.message.to_lowercase().contains(&filter_lower)
                        || e.raw.to_lowercase().contains(&filter_lower)
                })
                .collect()
        };

        let items: Vec<ListItem> = filtered
            .iter()
            .map(|e| Self::entry_to_list_item(e))
            .collect();

        let filter_indicator = if self.filter_mode {
            &format!(" [filter: '{}']", self.filter_text)[..]
        } else if !self.filter_text.is_empty() {
            &format!(" (filter: '{}')", self.filter_text)[..]
        } else {
            ""
        };

        let focused = self.focus == PanelFocus::LogList;
        let border_style = if focused {
            Style::new().fg(Color::Cyan)
        } else {
            Style::new().fg(Color::DarkGray)
        };

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!("Logs: {title}{filter_indicator}"))
                    .border_style(border_style),
            )
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED));

        frame.render_stateful_widget(list, area, &mut self.log_state);
    }
}

impl LogViewer {
    fn total_host_list_len(&self) -> usize {
        let mut len = 1 + self.virtual_hosts.len();
        if !self.system_logs.is_empty() {
            len += 1 + self.system_logs.len();
        }
        len
    }

    fn resolve_selection(&self, index: usize) -> Option<(String, SelectionType)> {
        let mut current = 0;

        current += 1;
        if index < current {
            return self
                .virtual_hosts
                .get(index)
                .map(|h| (h.name.clone(), SelectionType::VirtualHost));
        }

        if !self.system_logs.is_empty() {
            current += 1;
            if index < current + self.system_logs.len() {
                let sys_idx = index - current;
                return self
                    .system_logs
                    .get(sys_idx)
                    .map(|h| (h.name.clone(), SelectionType::SystemLog));
            }
        }

        None
    }

    /// The repository source kind for the current selection.
    fn source_kind(&self) -> LogSourceKind {
        match self.selection_type {
            SelectionType::SystemLog => LogSourceKind::SystemLog,
            SelectionType::VirtualHost => LogSourceKind::Vhost,
        }
    }

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

    /// Move the selection of the focused panel by `delta` positions, clamped
    /// to the panel bounds.
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

    fn handle_action(&mut self, action: &Action) -> Result<Option<Action>, SentinelError> {
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
                    let _ = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(self.load_recent_entries(&name))
                    });
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
                    let _ = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current()
                            .block_on(self.check_new_entries(&name, st))
                    });
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn draw(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        let main_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(25), Constraint::Percentage(75)])
            .split(area);

        self.render_host_list(frame, main_layout[0]);
        self.render_log_list(frame, main_layout[1]);
    }
}
