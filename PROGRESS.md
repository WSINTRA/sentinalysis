# PROGRESS.md - Sentinel Development Progress

## Status: Phase 2 - Log Scanner Core

### Completed

- [x] Project documentation created (SPEC.md, PLAN.md, AGENT.md, PROGRESS.md)
- [x] Rust project initialized with cargo
- [x] Dependencies configured in Cargo.toml
- [x] Git repository initialized
- [x] Project structure created
- [x] Error types implementation (src/error.rs) - 9 tests
- [x] LogParser trait and types (src/log_scanner/parser/mod.rs)
- [x] NginxAccessParser (src/log_scanner/parser/nginx.rs) - 25 tests
- [x] AuthLogParser (src/log_scanner/parser/auth.rs) - 14 tests
- [x] NoiseFilter with security detection (src/log_scanner/filter.rs) - 27 tests
- [x] Threat Classifier (src/log_scanner/classifier.rs) - 38 tests
- [x] FileTailer with notify-based watching (src/log_scanner/tailer.rs) - 11 tests

### In Progress

- [ ] Scanner orchestrator (src/log_scanner/mod.rs)
- [ ] Configuration loading (src/config.rs)
- [ ] Database pool setup (src/db/pool.rs)

### Next Steps

1. Implement FileTailer with notify crate
2. Wire up scanner orchestrator (parse -> filter -> classify -> store)
3. Implement config.rs with serde_yaml
4. Set up sqlx with Postgres and migrations

### Blockers

None.

### Notes

- Using `notify` crate instead of `inotify` (cross-platform, uses inotify on Linux)
- 123 tests passing total (1 ignored: flaky FSEvents on macOS)
- Clippy clean, rustfmt applied
- TDD workflow established: tests first, clippy/fmt on every commit
- FileTailer uses crossbeam-channel for thread-safe notify bridging
