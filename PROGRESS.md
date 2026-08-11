# PROGRESS.md - Sentinel Development Progress

## Status: Phases 1, 2, 2b, 4 Complete

### Completed

- [x] Project documentation created (SPEC.md, PLAN.md, AGENT.md, PROGRESS.md, README.md)
- [x] Rust project initialized with cargo
- [x] Dependencies configured in Cargo.toml
- [x] Git repository initialized
- [x] Project structure created
- [x] Error types implementation (src/error.rs) - 9 tests
- [x] LogParser trait and types (src/log_scanner/parser/mod.rs)
- [x] NginxAccessParser (src/log_scanner/parser/nginx.rs) - 25 tests (custom format with $host/$request_time)
- [x] AuthLogParser (src/log_scanner/parser/auth.rs) - 14 tests
- [x] NoiseFilter with security detection (src/log_scanner/filter.rs) - 27 tests
- [x] Threat Classifier (src/log_scanner/classifier.rs) - 38 tests
- [x] FileTailer with notify-based watching (src/log_scanner/tailer.rs) - 11 tests (2-channel design)
- [x] Scanner orchestrator (src/log_scanner/scanner.rs) - tail→parse→filter→classify→batch insert
- [x] Configuration loading (src/config.rs) - YAML with serde defaults
- [x] Database pool setup (src/db/pool.rs) - PgPool from DATABASE_URL
- [x] SQL migrations (migrations/20260810204714_initial_schema.sql) - full schema with indexes
- [x] DB models (src/db/models.rs) - query structs for all 6 tables
- [x] LogEntry repository (src/db/repositories/log_entry_repo.rs) - batch insert, raw_line for non-noise only
- [x] Service repository (src/db/repositories/service_repo.rs) - CRUD, get_or_create, find_by_virtual_host
- [x] ServiceDiscoverer (src/service_tracker/discoverer.rs) - systemd paths, user-created vs system classification
- [x] ServiceMonitor (src/service_tracker/monitor.rs) - systemctl show for ActiveState, MemoryCurrent, CPUUsageNSec, NRestart
- [x] JournalctlTailer (src/service_tracker/journalctl.rs) - sdjournal crate, LiveJournal with LiveSubscription

### In Progress

- [ ] System monitor (src/system_monitor/) - CPU, memory, disk, network metrics
- [ ] Alerting engine (src/alerting/) - rules, evaluation
- [ ] API layer (src/api/) - actix-web, TLS, auth, rate limiting

### Next Steps

1. Implement system_monitor module (metric collection via sysinfo, session tracking)
2. Implement alerting engine (alert rules, evaluation, notification)
3. Implement API layer (routes, TLS, API key auth, rate limiting)
4. Wire up main.rs with DI and graceful shutdown
5. Full integration tests

### Blockers

None.

### Notes

- 185 tests passing total (4 ignored: macOS FSEvents)
- Clippy clean, rustfmt applied
- TDD workflow established: tests first, clippy/fmt on every commit
- FileTailer uses crossbeam-channel for thread-safe notify bridging
- Scanner batch inserts every 100 entries or 1 second
- JournalctlTailer uses sdjournal crate (v0.1.15) for native journal reading
- README updated with nginx setup, systemd tracking, journalctl tailing docs
