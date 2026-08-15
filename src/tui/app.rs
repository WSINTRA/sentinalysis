//! The TUI application: composes the viewer and status bar components and
//! forwards the lifecycle calls (init / action / draw) to them.

use crate::error::SentinelError;
use crate::tui::action::Action;
use crate::tui::components::Composite;
use crate::tui::data::LogDataSource;

pub struct App {
    composite: Composite,
}

impl App {
    /// Compose the app around a data source. The production source is
    /// [`crate::tui::data::pg::PgLogDataSource`]; tests use the in-memory
    /// one.
    #[must_use]
    pub fn new<S: LogDataSource + Send + 'static>(data_source: S) -> Self {
        let composite = Composite::new(vec![
            Box::new(crate::tui::components::log_viewer::LogViewer::new(
                data_source,
            )),
            Box::new(crate::tui::components::status_bar::StatusBar::new()),
        ]);

        Self { composite }
    }

    pub async fn init(&mut self) -> Result<(), SentinelError> {
        self.composite.init().await?;
        Ok(())
    }

    pub async fn handle_action(&mut self, action: &Action) -> Result<(), SentinelError> {
        self.composite.handle_action(action).await
    }

    pub fn draw(&mut self, frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        self.composite.draw(frame, area);
    }
}
