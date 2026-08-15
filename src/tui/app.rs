//! The TUI application: composes the viewer and status bar components and
//! forwards the lifecycle calls (init / action / draw) to them.

use sqlx::PgPool;

use crate::error::SentinelError;
use crate::tui::action::Action;
use crate::tui::components::Composite;

pub struct App {
    composite: Composite,
}

impl App {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        let composite = Composite::new(vec![
            Box::new(crate::tui::components::log_viewer::LogViewer::new(pool)),
            Box::new(crate::tui::components::status_bar::StatusBar::new()),
        ]);

        Self { composite }
    }

    pub async fn init(&mut self) -> Result<(), SentinelError> {
        self.composite.init().await?;
        Ok(())
    }

    pub async fn handle_action(
        &mut self,
        action: &Action,
    ) -> Result<Option<Action>, SentinelError> {
        self.composite.handle_action(action).await
    }

    pub fn draw(&mut self, frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        self.composite.draw(frame, area);
    }
}
