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

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    /// Render the status bar into a test backend and return the buffer
    /// as one string per row.
    fn render_text(status_bar: &mut StatusBar, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| status_bar.draw(frame, Rect::new(0, 0, width, height)))
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let w = buffer.area.width as usize;
        (0..buffer.area.height)
            .map(|y| {
                buffer
                    .content()
                    .iter()
                    .skip((y as usize) * w)
                    .take(w)
                    .map(ratatui::buffer::Cell::symbol)
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn test_status_bar_shows_key_hints() {
        let mut bar = StatusBar::new();
        let text = render_text(&mut bar, 100, 3);
        // The hints render on the bottom row.
        assert!(text.contains("[q] quit"));
        assert!(text.contains("[↑↓] navigate"));
        assert!(text.contains("[/] filter"));
        assert!(text.contains("[r] refresh"));
        assert!(text.contains("[Esc] clear"));
    }

    #[test]
    fn test_status_bar_shows_transient_message() {
        let mut bar = StatusBar::new();
        bar.message = "3 entries loaded".to_string();
        let text = render_text(&mut bar, 100, 3);
        assert!(text.contains("3 entries loaded"));
        // The hints are still present alongside the message.
        assert!(text.contains("[q] quit"));
    }

    #[test]
    fn test_status_bar_ignores_actions() {
        let mut bar = StatusBar::new();
        let _ = bar.handle_action(&Action::Quit).await_ok();
        // Consumes nothing and mutates nothing.
        assert!(bar.message.is_empty());
    }

    /// Await a `BoxedFuture` inside a test without a runtime helper.
    trait AwaitOk {
        fn await_ok(self) -> Result<(), SentinelError>;
    }
    impl AwaitOk for BoxedFuture<'_, Result<(), SentinelError>> {
        fn await_ok(self) -> Result<(), SentinelError> {
            use futures::executor::block_on;
            block_on(self)
        }
    }
}
