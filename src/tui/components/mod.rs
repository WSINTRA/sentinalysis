use std::future::Future;

use ratatui::layout::Rect;

use crate::error::SentinelError;
use crate::tui::action::Action;

pub mod log_viewer;
pub mod status_bar;

pub trait Component: Send {
    fn init(&mut self) -> BoxedFuture<'_, Result<(), SentinelError>> {
        Box::pin(async { Ok(()) })
    }

    fn handle_action(&mut self, action: &Action) -> Result<Option<Action>, SentinelError> {
        let _ = action;
        Ok(None)
    }

    fn draw(&mut self, frame: &mut ratatui::Frame, area: Rect);
}

pub type BoxedFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

use std::pin::Pin;

pub struct Composite {
    components: Vec<Box<dyn Component>>,
}

impl Composite {
    #[must_use]
    pub fn new(components: Vec<Box<dyn Component>>) -> Self {
        Self { components }
    }

    pub async fn init(&mut self) -> Result<(), SentinelError> {
        for component in &mut self.components {
            component.init().await?;
        }
        Ok(())
    }

    pub fn handle_action(&mut self, action: &Action) -> Result<Option<Action>, SentinelError> {
        for component in &mut self.components {
            if let Some(next_action) = component.handle_action(action)? {
                return Ok(Some(next_action));
            }
        }
        Ok(None)
    }

    pub fn draw(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        for component in &mut self.components {
            component.draw(frame, area);
        }
    }
}
