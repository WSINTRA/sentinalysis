//! Sentinel: log monitoring and security analysis.
//!
//! The daemon tails configured log files, parses and classifies every
//! line, and stores the results in Postgres; the TUI renders the stored
//! entries. See the module docs of [`daemon`], [`tui`], and
//! [`log_scanner`] for the respective halves of the system.

pub mod config;
pub mod daemon;
pub mod db;
pub mod error;
pub mod log_scanner;
pub mod service_tracker;
pub mod setup;
pub mod tui;
