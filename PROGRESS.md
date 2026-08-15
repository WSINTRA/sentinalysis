# PROGRESS.md - Sentinel Development Progress

## Status: Core monitoring loop, TUI, and daemon complete

### Completed

- [x] Project documentation (SPEC.md, PLAN.md, AGENT.md, PROGRESS.md, README.md)
- [x] Error types (src/error.rs), configuration loading (src/config.rs)
- [x] Parsers: NginxAccessParser, AuthLogParser (src/log_scanner/parser/)
- [x] NoiseFilter: health checks, static assets, known bots (src/log_scanner/filter.rs)
- [x] Threat classifier: SQLi, XSS, path traversal, command injection, brute force, scanner UAs
- [x] FileTailer: notify-based watching, rotation aware (src/log_scanner/tailer/)
- [x] Source/SourceKind model + config-driven SourceDiscovery (shared by daemon and TUI)
- [x] Pipeline: per-line parse → filter → classify, honoring noise/security semantics
- [x] Scanner: batched stream → pipeline → repository (src/log_scanner/scanner.rs)
- [x] Postgres: migrations, pool, write/query/service repositories (src/db/)
- [x] Daemon mode: PID-file supervision, config forwarding, SIGTERM/SIGINT shutdown (src/daemon/)
- [x] TUI: ratatui two-panel log viewer, filtering, threat badges, status bar (src/tui/)
- [x] TUI data layer: LogDataSource trait with Postgres and in-memory implementations
- [x] Test suite: 261 passing (4 ignored on macOS FSEvents), incl. end-to-end pipeline
  integration test, TestBackend render tests, and in-memory viewer behavior tests
- [x] CI: GitHub Actions running fmt, clippy (-D warnings), and tests
- [x] Service tracker implementation (discoverer, monitor, sdjournal tailer) —
  built and tested, not yet wired into the daemon

### Next Steps

1. Wire service_tracker (discoverer + monitor + journalctl tailer) into the daemon
2. System monitor module (CPU, memory, disk, network via sysinfo)
3. Alerting engine (rules, evaluation, notification)
4. API layer (actix-web, TLS, API key auth, rate limiting)

### Blockers

None.

### Notes

- 261 tests passing (4 ignored: macOS FSEvents live-append tests)
- Clippy clean with `-D warnings`, rustfmt applied on every commit
- TDD workflow: tests first, `cargo fmt && cargo clippy --all-targets -- -D warnings
  && cargo test` green on every commit
- TUI polls the database at most every 2 s per selected source; the poll cursor
  is the newest on-screen entry (strict `(timestamp, id)` row-value comparison)
- Daemon is started on demand by the TUI; `SENTINEL_PID_FILE` overrides the
  default PID file location (/run/sentinel.pid)
