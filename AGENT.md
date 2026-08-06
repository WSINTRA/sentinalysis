# AGENT.md - Sentinel Development Guidelines

## Project Overview

Sentinel is a Rust-based server monitoring tool. This document guides development with consistent patterns and standards.

## Code Style

- Run `cargo fmt` before every commit
- Treat clippy warnings as errors: `cargo clippy -- -D warnings`
- Use `thiserror` for error types, never `unwrap()` in production code
- Document public functions with `///` comments
- Max line length: 100 characters

## Architecture Principles

### Separation of Concerns

Each module has a single responsibility:
- `log_scanner/`: Only log parsing, filtering, classification
- `system_monitor/`: Only system metrics collection
- `service_tracker/`: Only systemd service management
- `api/`: Only HTTP handling, no business logic
- `db/`: Only data persistence
- `alerting/`: Only alert rule evaluation

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
src/
├── main.rs           # Entry point, DI wiring only
├── lib.rs            # Public API, module declarations
├── config.rs         # Configuration types and loading
├── error.rs          # All error types
└── <domain>/
    ├── mod.rs        # Module public API
    ├── <component>.rs # Single responsibility
    └── tests.rs      # Integration tests (if needed)
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
