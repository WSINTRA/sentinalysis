use std::collections::HashMap;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use sqlx::PgPool;
use tokio::sync::mpsc::UnboundedSender;
use tracing::info;

use crate::error::SentinelError;
use crate::log_scanner::classifier::ThreatLevel;
use crate::log_scanner::parser::LogLevel;
use crate::tui::action::Action;
use crate::tui::app::{DisplayLogEntry, VirtualHostInfo, VirtualHostSource};
use crate::tui::components::{BoxedFuture, Component};

const MAX_ENTRIES_PER_HOST: usize = 1000;

#[derive(Debug, sqlx::FromRow)]
struct DbLogEntry {
    id: uuid::Uuid,
    timestamp: chrono::DateTime<chrono::Utc>,
    level: String,
    message: String,
    raw_line: Option<String>,
    virtual_host: String,
}

pub struct LogViewer {
    pool: PgPool,
    _entry_tx: UnboundedSender<DisplayLogEntry>,
    virtual_hosts: Vec<VirtualHostInfo>,
    host_state: ListState,
    log_entries: HashMap<String, Vec<DisplayLogEntry>>,
    log_state: ListState,
    selected_host: Option<String>,
    filter_mode: bool,
    filter_text: String,
}

impl LogViewer {
    #[must_use]
    pub fn new(pool: PgPool, entry_tx: UnboundedSender<DisplayLogEntry>) -> Self {
        let mut host_state = ListState::default();
        host_state.select(Some(0));

        let mut log_state = ListState::default();
        log_state.select(Some(0));

        Self {
            pool,
            _entry_tx: entry_tx,
            virtual_hosts: Vec::new(),
            host_state,
            log_entries: HashMap::new(),
            log_state,
            selected_host: None,
            filter_mode: false,
            filter_text: String::new(),
        }
    }

    async fn load_virtual_hosts(&mut self) -> Result<(), SentinelError> {
        let db_hosts: Vec<(String, i64)> = sqlx::query_as(
            r"
            SELECT s.virtual_host, COUNT(*) as cnt
            FROM log_entries le
            JOIN services s ON le.service_id = s.id
            WHERE s.virtual_host IS NOT NULL
            GROUP BY s.virtual_host
            ORDER BY cnt DESC
            ",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentinelError::DatabaseError(e.to_string()))?;

        self.virtual_hosts = db_hosts
            .into_iter()
            .map(|(name, _count)| VirtualHostInfo {
                name,
                source: VirtualHostSource::LogEntry,
                entry_count: MAX_ENTRIES_PER_HOST,
            })
            .collect();

        if self.virtual_hosts.is_empty() {
            self.virtual_hosts.push(VirtualHostInfo {
                name: "No logs yet".to_string(),
                source: VirtualHostSource::LogEntry,
                entry_count: 0,
            });
        }

        self.virtual_hosts.sort_by(|a, b| a.name.cmp(&b.name));

        info!("Loaded {} virtual hosts", self.virtual_hosts.len());
        Ok(())
    }

    async fn load_recent_entries(&mut self, host: &str) -> Result<(), SentinelError> {
        let db_entries: Vec<DbLogEntry> = sqlx::query_as(
            r"
            SELECT le.id, le.timestamp, le.level, le.message, le.raw_line, s.virtual_host
            FROM log_entries le
            JOIN services s ON le.service_id = s.id
            WHERE s.virtual_host = $1
            ORDER BY le.id DESC
            LIMIT $2
            ",
        )
        .bind(host)
        .bind(MAX_ENTRIES_PER_HOST.try_into().unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SentinelError::DatabaseError(e.to_string()))?;

        let entries: Vec<DisplayLogEntry> = db_entries.into_iter().map(Self::db_to_display).collect();

        info!("Loaded {} entries for '{host}'", entries.len());
        self.log_entries.insert(host.to_string(), entries);
        self.log_state.select(Some(0));
        Ok(())
    }

    fn db_to_display(db: DbLogEntry) -> DisplayLogEntry {
        let level = match db.level.as_str() {
            "debug" => LogLevel::Debug,
            "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            "critical" => LogLevel::Critical,
            "security" => LogLevel::Security,
            _ => LogLevel::Info,
        };

        DisplayLogEntry {
            id: db.id,
            timestamp: db.timestamp,
            level,
            threat_level: ThreatLevel::None,
            message: db.message,
            raw: db.raw_line.unwrap_or_default(),
            virtual_host: db.virtual_host,
            threat_categories: Vec::new(),
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
            Span::styled(threat_badge, Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
        ]);

        ListItem::new(line)
    }

    fn render_host_list(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .virtual_hosts
            .iter()
            .map(|h| {
                let source_icon = match h.source {
                    VirtualHostSource::LogEntry => "[L]",
                    VirtualHostSource::SystemdService => "[S]",
                    VirtualHostSource::JournalctlConfig => "[J]",
                };
                ListItem::new(Line::raw(format!("{source_icon} {}", h.name)))
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Virtual Hosts"))
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

        let items: Vec<ListItem> = filtered.iter().map(|e| Self::entry_to_list_item(e)).collect();

        let filter_indicator = if self.filter_mode {
            " [FILTER MODE]"
        } else if !self.filter_text.is_empty() {
            &format!(" (filter: '{}')", self.filter_text)[..]
        } else {
            ""
        };

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!("Logs: {title}{filter_indicator}")),
            )
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED));

        frame.render_stateful_widget(list, area, &mut self.log_state);
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
            return match action {
                Action::ClearFilter => {
                    self.filter_mode = false;
                    self.filter_text.clear();
                    Ok(None)
                }
                Action::ToggleFilter => {
                    self.filter_mode = false;
                    Ok(None)
                }
                Action::Quit => Ok(Some(Action::Quit)),
                _ => Ok(None),
            };
        }

        match action {
            Action::Quit => Ok(Some(Action::Quit)),
            Action::SelectUp => {
                if let Some(i) = self.host_state.selected() {
                    self.host_state.select(Some(i.saturating_sub(1)));
                }
                Ok(None)
            }
            Action::SelectDown => {
                if let Some(i) = self.host_state.selected() {
                    self.host_state
                        .select(Some((i + 1).min(self.virtual_hosts.len().saturating_sub(1))));
                }
                Ok(None)
            }
            Action::Refresh => {
                if let Some(selected) = self.host_state.selected()
                    && let Some(host) = self.virtual_hosts.get(selected).map(|h| h.name.clone())
                {
                    self.selected_host = Some(host);
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
                    let max = self
                        .selected_host
                        .as_ref()
                        .and_then(|h| self.log_entries.get(h).map(|v| v.len().saturating_sub(1)))
                        .unwrap_or(0);
                    self.log_state.select(Some((i + 20).min(max)));
                }
                Ok(None)
            }
            Action::ScrollToTop => {
                self.log_state.select(Some(0));
                Ok(None)
            }
            Action::ScrollToBottom => {
                if let Some(max) = self
                    .selected_host
                    .as_ref()
                    .and_then(|h| self.log_entries.get(h).map(|v| v.len().saturating_sub(1)))
                {
                    self.log_state.select(Some(max));
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
