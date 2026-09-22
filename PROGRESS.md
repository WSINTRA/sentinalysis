# PROGRESS.md - Sentinel Development Progress

## Status: TUI + daemon + hub + agent modes complete; SPA built; alerting/sessions pending

The project pivoted from the original API-only design to a **hub-and-agent
architecture** with a TUI front end for local use. Both local ingestion
(daemon → Postgres → TUI) and remote ingestion (agent → hub gRPC → Postgres →
React dashboard) are implemented and tested. Remaining work: service-tracker
wiring, alerting, session tracking, hub TLS termination, and packaging.

### Completed

- [x] Project documentation (SPEC.md, PLAN.md, AGENTS.md, PROGRESS.md, README.md,
  HUB_PLAN.md, SDK_PLAN.md, WEB_UI.md)
- [x] Error types (src/error.rs), configuration loading (src/config.rs,
  incl. `hub:` and `agent:` sections with bind-security validation)
- [x] Parsers: NginxAccessParser (extracts `$host` vhost + `$request_time`), AuthLogParser
- [x] NoiseFilter: health checks, static assets, known bots (src/log_scanner/filter.rs)
- [x] Threat classifier: SQLi, XSS, path traversal, command injection, brute force, scanner UAs
- [x] FileTailer: notify-based watching, rotation aware (src/log_scanner/tailer/)
- [x] Source/SourceKind model + config-driven SourceDiscovery (shared by daemon and TUI)
- [x] Pipeline: per-line parse → filter → classify; Scanner: batched stream → repository
- [x] Postgres: migrations (initial schema, threat columns, hub tables), pool,
  repositories (log entry/query, service, system metric, agent, app event, API key)
- [x] Daemon mode: PID-file supervision, config forwarding, SIGTERM/SIGINT shutdown (src/daemon/)
- [x] TUI: ratatui two-panel log viewer, text filtering, threat badges, status bar (src/tui/);
  LogDataSource trait with Postgres and in-memory implementations
- [x] Hub mode (`--hub`, src/hub/): gRPC ingestion (tonic), actix REST API
  (health, event ingest, metrics/events/servers/summary reads), API-key auth
  (sha2 `key_id` lookup → argon2 verify, governor rate limiting), age-based
  retention jobs, SPA static serving, startup guard refusing public binds without TLS
- [x] `sentinel hub-key create/list/revoke` CLI (src/hub/keys_cli.rs) — raw key
  printed exactly once; only hash + public key_id stored
- [x] Agent mode (`--agent`, src/agent/): sysinfo metrics every 30 s, Docker
  container JSON-log discovery/tailing, bounded batcher with reconnect and
  shutdown flush, gRPC forwarding
- [x] proto/sentinel.proto + tonic-build codegen (build.rs); the wire protocol
  carries no identity fields — identity comes from the key row
- [x] React SPA (web/): KeyGate unlock screen (X-API-KEY, sessionStorage),
  Dashboard/Events/Servers pages; lint + build in CI
- [x] CI: `.github/workflows/ci.yml` — fmt, clippy `-D warnings`, test,
  plus web lint/build
- [x] Hub runs migrations on startup (`sqlx::migrate!` in `hub/run_hub.rs`)
- [x] Service tracker implementation (discoverer, monitor, sdjournal tailer) —
  built and unit-tested, **not yet wired into the daemon**

### Gaps

#### A. Feature gaps (planned, not built)

| Area | State | Evidence |
|------|-------|----------|
| Service tracker wiring | Built & tested, not connected to daemon/TUI | no `service_tracker` references outside its own module |
| Local system monitor | `src/system_monitor/` empty; remote metrics covered by the agent | `SystemMetric` model used by hub ingestion |
| Alerting | Not started | `Alert` model + `alerts` table exist; no rules/evaluator/notifier |
| Session tracking | Not started | `ActiveSession` model + `active_sessions` table exist; no `who`/`w` parsing |
| Hub TLS termination | `hub.tls` is configured and bind security validated, but no rustls acceptor is wired | no `rustls`/`Acceptor` references in `src/hub` |

#### B. TUI gaps (within the built feature)

- Reserved actions unimplemented: `ScrollUp`, `ScrollDown`, `LogEntryAdded`,
  `LoadOlderEntries` (`tui/action.rs`).
- No history pagination: list is newest-first capped at `MAX_ENTRIES_PER_HOST = 1000`
  (`tui/components/log_viewer/mod.rs`); cannot scroll older than the in-memory cache.
- Entry counts are now populated end-to-end (`count_entries` → `SourceInfo`,
  `tui/data/pg.rs`) but are still not rendered in the sources panel.
- Filter is client-side substring only over the <=1000 cached rows; no
  level/threat/status filter, and nothing outside the loaded window.

#### C. Database / operational gaps

- Daemon/TUI modes do not run migrations at startup (the hub does); a fresh
  Postgres still needs a manual `cargo sqlx migrate run` for local modes.
- No `config.example.yaml` / `.env.example` committed (CLI defaults to
  `config.yaml` and requires `DATABASE_URL`; `.env` is gitignored).
- No packaging: no Dockerfile, no systemd `.service` units (SDK_PLAN.md
  describes the intended hardened non-root agent unit), no Makefile/justfile.

#### D. Code hygiene

- Unused dependencies: `ring`, `actix-tls` — declared in Cargo.toml with zero
  references in `src`.
- Empty module dirs: `src/api/handlers/`, `src/alerting/`, `src/system_monitor/`.
- SPEC.md is stale: still presents the pre-pivot design (REST :8443 endpoint
  list, `inotify` crate, no TUI/hub/agent/gRPC, "Web UI" and "multi-server
  aggregation" listed as non-goals).
- PLAN.md is stale: Phase 6 (API) and Phase 7 (Integration) marked Pending
  although the hub API and CLI integration exist; no phases track the
  TUI/daemon/hub/agent/SPA work.

### Next Steps

Prioritized by leverage (each item is independently shippable):

1. **Wire `service_tracker` into the daemon** — discoverer + monitor +
   journalctl tailer are already built and tested; connect them in
   `daemon/run.rs`, persist to `services`/`log_entries`, and surface them as
   a `SourceKind` in the TUI.
2. **Run migrations on startup for daemon/TUI** — the hub already does
   (`run_hub.rs`); do the same in `db/pool.rs` or `main.rs`.
3. **Drop unused deps and empty dirs** — remove `ring` and `actix-tls` from
   Cargo.toml; delete or populate `src/api/`, `src/alerting/`,
   `src/system_monitor/`.
4. **Hub TLS termination** — wire a rustls acceptor for `hub.tls`
   (config and the bind guard already exist).
5. **TUI: render entry counts** in the sources panel (data is already there).
6. **TUI: history pagination** — implement `LoadOlderEntries` to page beyond
   the 1000-row cap.
7. **Alerting engine** — rules, evaluation over stored entries, notification.
8. **Session tracking** — parse `who`/`w` → `active_sessions` + a TUI view.
9. **Packaging** — systemd units (agent per SDK_PLAN.md, hub), Dockerfile,
   `config.example.yaml` + `.env.example`.
10. **Sync SPEC.md / PLAN.md** with the hub-and-agent architecture.

### Blockers

None.

### Notes

- Tests: per-module unit tests plus `tests/pipeline_integration.rs` and
  `tests/hub_e2e.rs`; a few macOS FSEvents live-append tests are ignored.
  Refresh the total count on the next full `cargo test` run.
- Clippy clean with `-D warnings`, rustfmt applied on every commit (enforced
  in CI).
- TDD workflow: tests first, `cargo fmt && cargo clippy --all-targets -- -D
  warnings && cargo test` green on every commit.
- TUI polls the database at most every 2 s per selected source; the poll
  cursor is the newest on-screen entry (strict `(timestamp, id)` comparison).
- Daemon is started on demand by the TUI; `SENTINEL_PID_FILE` overrides the
  default PID file location (/run/sentinel.pid).
- Hub binds `127.0.0.1` by default (gRPC :50051, REST :8080). Public binds
  without TLS are refused at startup; Tailscale (CGNAT) binds without TLS are
  allowed with a loud warning.
- Agent identity: the API key row carries `agent_id`/`hostname` (or
  `app_name` for app keys); nothing identity-shaped crosses the wire, so
  agents and apps cannot spoof each other.
