//! Bottom status line: key hints plus an optional transient message.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Wrap};

use crate::error::SentinelError;
use crate::tui::action::Action;
use crate::tui::components::{BoxedFuture, Component};

#[derive(Default)]
pub struct StatusBar {
    message: String,
}

impl StatusBar {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn render(&self, frame: &mut ratatui::Frame, area: Rect) {
        let keys = "[q] quit  [↑↓] navigate  [Enter] select  [/] filter  [r] refresh  [Esc] clear";

        let line = if self.message.is_empty() {
            Line::raw(keys)
        } else {
            Line::raw(format!("{keys}  |  {}", self.message))
        };

        let para = Paragraph::new(line)
            .style(Style::new().add_modifier(Modifier::REVERSED))
            .wrap(Wrap { trim: true });

        frame.render_widget(para, area);
    }
}

impl Component for StatusBar {
    fn handle_action<'a>(
        &'a mut self,
        _action: &'a Action,
    ) -> BoxedFuture<'a, Result<(), SentinelError>> {
        Box::pin(async { Ok(()) })
    }

    fn draw(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(1)])
            .split(area);

        self.render(frame, layout[1]);
    }
}
