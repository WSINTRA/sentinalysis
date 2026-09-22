# PROGRESS.md - Sentinel Development Progress

## Status: TUI + daemon log-monitoring core complete; broader features in progress

The current revision pivoted Sentinel from an API-only design to a **Ratatui/crossterm
TUI** fronted by a **background daemon** that tails logs and persists parsed, classified
entries to Postgres. The ingestion loop and the TUI viewer are complete and well-tested;
several SPEC feature areas remain unbuilt (see Gaps below).

### Completed

- [x] Project documentation (SPEC.md, PLAN.md, AGENTS.md, PROGRESS.md, README.md)
- [x] Error types (src/error.rs), configuration loading (src/config.rs)
- [x] Parsers: NginxAccessParser (now extracts `$host` vhost + `$request_time`), AuthLogParser
- [x] NoiseFilter: health checks, static assets, known bots (src/log_scanner/filter.rs)
- [x] Threat classifier: SQLi, XSS, path traversal, command injection, brute force, scanner UAs
- [x] FileTailer: notify-based watching, rotation aware (src/log_scanner/tailer/)
- [x] Source/SourceKind model + config-driven SourceDiscovery (shared by daemon and TUI)
- [x] Pipeline: per-line parse → filter → classify, honoring noise/security semantics
- [x] Scanner: batched stream → pipeline → repository (src/log_scanner/scanner.rs)
- [x] Postgres: migrations, pool, write/query/service repositories (src/db/)
- [x] Daemon mode: PID-file supervision, config forwarding, SIGTERM/SIGINT shutdown (src/daemon/)
- [x] TUI: ratatui two-panel log viewer, text filtering, threat badges, status bar (src/tui/)
- [x] TUI data layer: LogDataSource trait with Postgres and in-memory implementations
- [x] Test suite: 261 passing (4 ignored on macOS FSEvents), incl. end-to-end pipeline
  integration test, TestBackend render tests, and in-memory viewer behavior tests
- [x] Service tracker implementation (discoverer, monitor, sdjournal tailer) —
  built and unit-tested, **not yet wired into the daemon**
- [ ] CI: documented as GitHub Actions, but **no `.github/workflows/` present in the repo**

### Gaps

#### A. Feature gaps (planned in SPEC, not built)

| Area | State | Evidence |
|------|-------|----------|
| Service tracker wiring | Built & tested, not connected to daemon/TUI | `service_tracker/mod.rs:1` "not yet wired in" |
| System monitor (CPU/mem/disk/net) | Not started | No `system_monitor/` module; `sysinfo` unused; `SystemMetric` model unused (`db/models.rs:5`) |
| Alerting | Not started | `Alert` model + `alerts` table exist; no rules/evaluator/notifier |
| Session tracking | Not started | `ActiveSession` model + `active_sessions` table exist; no `who`/`w` parsing |
| REST API (actix) | Deferred | `actix-web` unused |

#### B. TUI gaps (within the built feature)

- Reserved actions unimplemented: `ScrollUp`, `ScrollDown`, `LogEntryAdded`,
  `LoadOlderEntries` (`tui/action.rs:5-6`).
- No history pagination: list is newest-first capped at `MAX_ENTRIES_PER_HOST = 1000`
  (`tui/components/log_viewer/mod.rs:25`); cannot scroll older than the in-memory cache.
- Entry count fetched but never displayed: `count_entries()` runs a per-source DB query on
  every `sources()` call (`db/repositories/log_query_repo.rs:89`), but the sources panel only
  renders `[L]/[S] <name>` (`tui/components/log_viewer/render.rs:38-48`); `SourceInfo.entry_count`
  is read nowhere in the UI (dead query + dead field).
- Filter is client-side substring only over the <=1000 cached rows (message/raw,
  `render.rs:81-92`); no level/threat/status filter, and nothing outside the loaded window.

#### C. Database / operational gaps

- No migration runner at startup: no `migrate!()`/`Migrator` anywhere in `src`; `db/pool.rs`
  and `main.rs` only `PgPool::connect`. A fresh Postgres is never auto-migrated — relies on a
  manual `sqlx migrate run`.
- No example config / `.env.example` committed (CLI defaults to `config.yaml` and requires
  `DATABASE_URL`, `main.rs:44`; `.env` is gitignored).
- No packaging: no Dockerfile, no systemd `.service` unit, no Makefile/justfile.

#### D. Code hygiene

- 6 unused dependencies declared and compiled: `actix-web`, `actix-tls` (-> rustls),
  `governor`, `argon2`, `ring`, `sysinfo` — zero references in `src` (README:238 notes
  actix/rustls/sysinfo are "declared for the planned API").
- CI discrepancy: claimed as GitHub Actions, but `.github/` is absent from the tree.
- SPEC.md is stale: still presents the actix REST API as a core feature (SPEC.md:80,121,131)
  and lists monitor/sessions/alerting as primary; the TUI-first pivot is only in README + PROGRESS.

### Next Steps

Prioritized by leverage (each item is independently shippable):

1. **Wire `service_tracker` into the daemon** — discoverer + monitor + journalctl tailer are
   already built and tested; connect them in `daemon/run.rs`, persist to `services`/`log_entries`,
   and surface them as a `SourceKind` in the TUI.
2. **Run migrations on startup** — add `sqlx::migrate!().run(&pool)` in `db/pool.rs` (or
   `main.rs`) so a fresh Postgres is usable without manual setup.
3. **Drop the 6 unused deps** (`actix-web`, `actix-tls`, `governor`, `argon2`, `ring`, `sysinfo`)
   to shrink the build until the API / system-monitor work actually lands.
4. **TUI: show entry counts or drop the query** — either render `entry_count` in the sources
   panel or stop calling `count_entries()` (dead query today).
5. **TUI: history pagination** — implement `LoadOlderEntries` to page beyond the 1000-row cap.
6. **System monitor module** — CPU/mem/disk/net via `sysinfo` -> `system_metrics` + a TUI panel.
7. **Alerting engine** — rules, evaluation over stored entries, notification.
8. **Session tracking** — parse `who`/`w` -> `active_sessions` + a TUI view.
9. **REST API (actix)** — TLS, API-key auth (argon2), rate limiting (governor); revive the
   relevant deps when starting this.
10. **Add CI + config/packaging** — commit `.github/workflows/ci.yml` running `fmt --check`,
    `clippy --all-targets -- -D warnings`, and `test`; add `config.example.yaml` + `.env.example`;
    add a systemd unit and/or Dockerfile for deployment.
11. **Sync SPEC.md** with the TUI-first architecture (or split into SPEC-tui / SPEC-api).

### Blockers

None.

### Notes

- 261 tests passing (4 ignored: macOS FSEvents live-append tests). *Not re-verified in this
  review (no shell access); taken from README/PROGRESS.*
- Clippy clean with `-D warnings`, rustfmt applied on every commit (per README; not re-run here).
- TDD workflow: tests first, `cargo fmt && cargo clippy --all-targets -- -D warnings
  && cargo test` green on every commit.
- TUI polls the database at most every 2 s per selected source; the poll cursor is the newest
  on-screen entry (strict `(timestamp, id)` row-value comparison).
- Daemon is started on demand by the TUI; `SENTINEL_PID_FILE` overrides the default PID file
  location (/run/sentinel.pid).
- Nginx access parser now handles an optional trailing `"host" request_time` pair, so per-vhost
  grouping and response-time capture work (previously always `None`).
