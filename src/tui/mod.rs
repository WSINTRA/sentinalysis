//! Ratatui/crossterm terminal user interface.
//!
//! [`Tui`] owns the terminal and the event loop; [`app::App`] composes the
//! stateful components that respond to events.

pub mod action;
pub mod app;
pub mod components;
pub mod terminal;

pub use terminal::Tui;
