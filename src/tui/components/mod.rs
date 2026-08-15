//! TUI building blocks: the [`Component`] trait and the [`Composite`]
//! container that runs a list of them.
//!
//! `handle_action` is async on purpose: actions that need I/O (loading
//! entries, polling for new ones) await it directly instead of blocking
//! the runtime worker thread with `block_in_place`.
//!
//! Every component receives every action and decides for itself whether
//! it cares; `Quit` is handled by the terminal event loop before
//! dispatch, so components never see it.

use std::future::Future;
use std::pin::Pin;

use ratatui::layout::Rect;

use crate::error::SentinelError;
use crate::tui::action::Action;

pub mod log_viewer;
pub mod status_bar;

pub trait Component: Send {
    fn init(&mut self) -> BoxedFuture<'_, Result<(), SentinelError>> {
        Box::pin(async { Ok(()) })
    }

    /// Handle an action. Both borrows share one lifetime so the returned
    /// future can outlive neither `self` nor `action`.
    fn handle_action<'a>(
        &'a mut self,
        action: &'a Action,
    ) -> BoxedFuture<'a, Result<(), SentinelError>>;

    fn draw(&mut self, frame: &mut ratatui::Frame, area: Rect);
}

pub type BoxedFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Runs a fixed set of components: every action is sent to each
/// component in order, and every component draws on every frame.
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

    pub async fn handle_action(&mut self, action: &Action) -> Result<(), SentinelError> {
        for component in &mut self.components {
            component.handle_action(action).await?;
        }
        Ok(())
    }

    pub fn draw(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        for component in &mut self.components {
            component.draw(frame, area);
        }
    }
}
