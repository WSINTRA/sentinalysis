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
use crate::tui::data::DisplayLogEntry;

use super::{LogViewer, PanelFocus};

impl LogViewer {
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
