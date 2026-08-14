//! Log ingestion: tail files → parse lines → filter noise → classify
//! threats → batch-persist.
//!
//! The per-line work is the pure [`pipeline::Pipeline`] (unit-testable
//! with in-memory fakes); the [`scanner::Scanner`] adds batching; the
//! daemon wires real I/O around both.

pub mod classifier;
pub mod filter;
pub mod parser;
pub mod pipeline;
pub mod scanner;
pub mod tailer;
