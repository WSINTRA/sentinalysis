# AGENTS.md - Sentinel Development Guidelines

## Project Overview

Sentinel is a Rust-based server monitoring tool with four modes in one
binary: `--tui` (terminal viewer), `--daemon` (local log scanner), `--hub`
(gRPC/REST central server + dashboard), and `--agent` (remote forwarder),
plus a `hub-key` subcommand for API key management. This document guides
development with consistent patterns and standards.

## Code Style

- Run `cargo fmt` before every commit
- Treat clippy warnings as errors: `cargo clippy -- -D warnings`
- Use `thiserror` for error types, never `unwrap()` in production code
- Document public functions with `///` comments
- Max line length: 100 characters

## Architecture Principles

### Separation of Concerns

Each module has a single responsibility:
- `log_scanner/`: Only log tailing, parsing, filtering, classification
- `daemon/`: Only process supervision and the tailer → scanner loop
- `hub/`: Only ingestion servers, API auth, retention, SPA serving —
  no classification or filtering logic
- `agent/`: Only metric/log collection and gRPC forwarding; no identity of
  its own beyond its API key
- `tui/`: Only rendering and key handling; data via the `LogDataSource` trait
- `db/`: Only data persistence
- `service_tracker/`: Only systemd service management (not yet wired)
- `alerting/`, `system_monitor/`: Reserved, not yet implemented

### Dependency Injection via Traits

Components depend on traits, not concrete types:

```rust
// Define the contract
pub trait LogParser: Send + Sync {
    fn parse(&self, line: &str) -> Result<Option<ParsedLogEntry>, ParseError>;
}

// Depend on the trait
pub struct Scanner<P: LogParser> {
    parser: P,
}

// Inject concrete type at runtime
let scanner = Scanner { parser: NginxAccessParser };
```

### Error Handling

- Use `Result<T, SentinelError>` for fallible operations
- Define errors in `src/error.rs` as a single enum
- Use `thiserror` for derive macros
- Log errors with context, don't silently ignore

### Testing

- TDD: Write failing test → minimal implementation → refactor
- Unit tests in `#[cfg(test)]` modules at bottom of each file
- Use `rstest` for parameterized tests
- Use `proptest` for property-based tests on parsers
- Mock external dependencies (DB, file system, network)
- Test names: `function_name_condition_expected_result`

### Async Patterns

- Use `tokio` for all async operations
- Use `tokio::select!` for concurrent operations
- Use `tokio::spawn` for background tasks
- Use channels (`tokio::sync::mpsc`) for inter-component communication
- Avoid blocking calls in async context (use `tokio::task::spawn_blocking`)

## Naming Conventions

- Modules: snake_case (`log_scanner`, `system_monitor`)
- Structs: PascalCase (`NginxAccessParser`, `LogEntry`)
- Traits: PascalCase with descriptive names (`LogParser`, `Repository`)
- Functions: snake_case (`parse_line`, `collect_metrics`)
- Tests: `test_` prefix with description (`test_parses_combined_log_format`)
- Constants: SCREAMING_SNAKE_CASE (`DEFAULT_POLL_INTERVAL`)

## File Organization

```
proto/sentinel.proto  # gRPC contract (tonic-build via build.rs)
migrations/           # Postgres schema (sqlx)
web/                  # React SPA dashboard (Vite; served by the hub)
src/
├── main.rs           # CLI entry: mode flags + hub-key subcommand
├── lib.rs            # Public API, module declarations
├── config.rs         # Configuration types and loading
├── error.rs          # All error types
├── setup.rs          # Tracing init, config loading
├── daemon/           # Daemon mode (process supervision, scan loop)
├── db/               # Pool + repositories
├── log_scanner/      # Tailer, parsers, filter, classifier, pipeline
├── hub/              # gRPC/REST servers, auth, retention, keys CLI
├── agent/            # Metrics, Docker logs, batched gRPC forwarding
├── service_tracker/  # Systemd discovery/monitor/journalctl (unwired)
└── tui/              # ratatui interface
    └── <domain>/
        ├── mod.rs    # Module public API
        ├── <component>.rs # Single responsibility
        └── tests.rs  # Integration tests (if needed)
```

## Git Workflow

- Commit after each passing test suite
- Commit messages: "feat: add nginx parser", "test: add noise filter tests"
- One logical change per commit
- Run `cargo fmt && cargo clippy -- -D warnings && cargo test` before committing

## Security

- Never log secrets or credentials
- Validate all external input (config, API requests)
- Use constant-time comparison for auth tokens
- Bind API to localhost by default
- TLS for all API communication
- The API key IS the identity: the `api_keys` row carries the trusted
  `agent_id`/`hostname`/`app_name` and permissions. Never add identity
  fields to the wire protocol (see HUB_PLAN.md "Security Model")
- Raw API keys are printed once at creation and stored only as an argon2
  hash plus the public `key_id` lookup prefix
