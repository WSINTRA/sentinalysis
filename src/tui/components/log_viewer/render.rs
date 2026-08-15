//! Frame drawing for the log viewer: the sources panel (left, 25%) and the
//! entry list (right, 75%).
//!
//! Pure presentation — it reads viewer state and only mutates ratatui's
//! list selection state via `render_stateful_widget`.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem};

use crate::log_scanner::classifier::ThreatLevel;
use crate::log_scanner::parser::LogLevel;
use crate::tui::data::{DisplayLogEntry, LogDataSource};

use super::{LogViewer, PanelFocus};

impl<D: LogDataSource> LogViewer<D> {
    pub(super) fn render(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        let main_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(25), Constraint::Percentage(75)])
            .split(area);

        self.render_host_list(frame, main_layout[0]);
        self.render_log_list(frame, main_layout[1]);
    }

    fn render_host_list(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        let mut items: Vec<ListItem> = Vec::new();

        items.push(ListItem::new(
            Line::raw("Virtual Hosts").style(Style::new().add_modifier(Modifier::BOLD)),
        ));
        if self.virtual_hosts.is_empty() && self.system_logs.is_empty() {
            items.push(ListItem::new(Line::raw("No log sources found")));
        }
        for h in &self.virtual_hosts {
            items.push(ListItem::new(Line::raw(format!("[L] {}", h.source.name))));
        }

        if !self.system_logs.is_empty() {
            items.push(ListItem::new(
                Line::raw("System Logs").style(Style::new().add_modifier(Modifier::BOLD)),
            ));
            for h in &self.system_logs {
                items.push(ListItem::new(Line::raw(format!("[S] {}", h.source.name))));
            }
        }

        let border_style = if self.focus == PanelFocus::HostList {
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
        let title = self
            .selected_source
            .as_ref()
            .map_or("No source selected", |s| s.name.as_str());

        let entries = self
            .selected_source
            .as_ref()
            .and_then(|s| self.log_entries.get(&s.name).map(Vec::as_slice))
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
            .copied()
            .map(Self::entry_to_list_item)
            .collect();

        let filter_indicator = if self.filter_mode {
            &format!(" [filter: '{}']", self.filter_text)[..]
        } else if !self.filter_text.is_empty() {
            &format!(" (filter: '{}')", self.filter_text)[..]
        } else {
            ""
        };

        let border_style = if self.focus == PanelFocus::LogList {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_scanner::classifier::ThreatLevel;
    use crate::log_scanner::parser::LogLevel;
    use crate::log_scanner::source::SourceKind;
    use crate::tui::components::Component;
    use crate::tui::data::SourceInfo;
    use crate::tui::data::memory::MemoryLogDataSource;
    use chrono::Utc;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use uuid::Uuid;

    type TestViewer = LogViewer<MemoryLogDataSource>;

    fn entry(message: &str, threat: ThreatLevel, categories: Vec<String>) -> DisplayLogEntry {
        DisplayLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            level: LogLevel::Info,
            threat_level: threat,
            message: message.to_string(),
            raw: String::new(),
            source_name: "a.example.com".to_string(),
            threat_categories: categories,
        }
    }

    /// A viewer with one vhost (two entries, one a threat) and one system
    /// log, initialised from the data source.
    async fn viewer_with_sources() -> TestViewer {
        let ds = MemoryLogDataSource::new()
            .with_sources(
                vec![SourceInfo::new(SourceKind::Vhost, "a.example.com", 2)],
                vec![SourceInfo::new(SourceKind::SystemLog, "auth.log", 0)],
            )
            .with_entries(
                "a.example.com",
                vec![
                    entry(
                        "sql injection attempt",
                        ThreatLevel::High,
                        vec!["sql-injection".to_string()],
                    ),
                    entry("GET / 200", ThreatLevel::None, Vec::new()),
                ],
            );
        let mut v = LogViewer::new(ds);
        v.init().await.unwrap();
        v
    }

    fn render_to_buffer(viewer: &mut TestViewer) -> Buffer {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| viewer.draw(frame, Rect::new(0, 0, 100, 30)))
            .unwrap();
        terminal.backend().buffer().clone()
    }

    fn buffer_text(buffer: &Buffer) -> String {
        let width = buffer.area.width as usize;
        (0..buffer.area.height)
            .map(|y| {
                buffer
                    .content()
                    .iter()
                    .skip((y as usize) * width)
                    .take(width)
                    .map(ratatui::buffer::Cell::symbol)
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[tokio::test]
    async fn test_host_list_shows_headers_and_sources() {
        let mut v = viewer_with_sources().await;
        let text = buffer_text(&render_to_buffer(&mut v));

        assert!(text.contains("Virtual Hosts"));
        assert!(text.contains("[L] a.example.com"));
        assert!(text.contains("System Logs"));
        assert!(text.contains("[S] auth.log"));
        assert!(text.contains("Sources"));
    }

    #[test]
    fn test_empty_sources_show_notice() {
        let mut v = LogViewer::new(MemoryLogDataSource::new());
        let text = buffer_text(&render_to_buffer(&mut v));

        assert!(text.contains("No log sources found"));
    }

    #[tokio::test]
    async fn test_focus_border_is_cyan_on_focused_panel() {
        // HostList is the default focus: the left border (x=0) is cyan.
        let mut v = viewer_with_sources().await;
        let buffer = render_to_buffer(&mut v);
        assert_eq!(buffer.cell((0, 10)).unwrap().fg, Color::Cyan);

        // Focusing the log panel dims the host list border.
        v.focus = PanelFocus::LogList;
        let buffer = render_to_buffer(&mut v);
        assert_eq!(buffer.cell((0, 10)).unwrap().fg, Color::DarkGray);
        // The log panel's left border (x=25) becomes cyan.
        assert_eq!(buffer.cell((25, 10)).unwrap().fg, Color::Cyan);
    }

    #[tokio::test]
    async fn test_log_list_title_and_entries() {
        let mut v = viewer_with_sources().await;
        let text = buffer_text(&render_to_buffer(&mut v));

        assert!(text.contains("Logs: a.example.com"));
        assert!(text.contains("sql injection attempt"));
        assert!(text.contains("GET / 200"));
        // Threats carry their category badge.
        assert!(text.contains("[sql-injection]"));
    }

    #[tokio::test]
    async fn test_filter_indicator_in_title() {
        let mut v = viewer_with_sources().await;
        v.filter_mode = true;
        v.filter_text = "sql".to_string();

        let text = buffer_text(&render_to_buffer(&mut v));

        assert!(text.contains("[filter: 'sql']"));
        // The non-matching entry is hidden.
        assert!(text.contains("sql injection attempt"));
        assert!(!text.contains("GET / 200"));
    }

    #[tokio::test]
    async fn test_no_selection_shows_placeholder_title() {
        let mut v = viewer_with_sources().await;
        v.selected_source = None;

        let text = buffer_text(&render_to_buffer(&mut v));

        assert!(text.contains("No source selected"));
    }
}
