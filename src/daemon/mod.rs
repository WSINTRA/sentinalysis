//! Daemon mode: tails configured log files, runs the scanner pipeline,
//! and persists entries to the database until a shutdown signal arrives.
//!
//! The daemon identifies itself with a PID file so the TUI can start it
//! on demand (`ensure_daemon_running`).
//!
//! - [`process`] owns process supervision: the PID file, liveness checks,
//!   and spawning the daemon as a child process.
//! - [`run`] owns the daemon's own execution: the tailer, scanner loop,
//!   and shutdown handling.

pub mod process;
pub mod run;

pub use process::ensure_daemon_running;
pub use run::run_daemon;
