# PLAN.md - Sentinel Implementation Plan

## Phase 1: Foundation (Complete)

- [x] Create project documentation (SPEC.md, PLAN.md, AGENT.md, PROGRESS.md)
- [x] Initialize Rust project with cargo
- [x] Configure dependencies in Cargo.toml
- [x] Git init
- [x] Implement error types (error.rs)
  - Test: Error enum variants, Display/Debug, From conversions
- [x] Implement configuration loading (config.rs)
  - Test: Valid YAML parsing, invalid YAML errors, defaults
- [x] Database pool setup (db/pool.rs)
  - Test: Connection creation, health check
- [x] SQL migrations
  - Test: Schema creation, basic CRUD

## Phase 2: Log Scanner Core (Complete)

- [x] LogParser trait definition
  - Test: Trait object behavior
- [x] NginxAccessParser (custom combined format with $host/$request_time)
  - Test: Combined log format parsing, edge cases, malformed lines
- [ ] NginxErrorParser
  - Test: Severity extraction, timestamp parsing
- [x] AuthLogParser
  - Test: Login success/fail detection
- [x] NoiseFilter
  - Test: IP matching, path regex, user-agent filtering
- [x] Classifier
  - Test: Level assignment, security pattern detection
- [x] FileTailer (notify-based, cross-platform)
  - Test: File following, rotation handling
- [x] LogEntry repository
  - Test: Batch insert, query by time/service/level, raw_line for non-noise only
- [x] Scanner orchestrator
  - Test: Full parse→filter→classify→store pipeline, batch every 100 entries or 1s

## Phase 2b: DB Integration (Complete)

- [x] PgPool from DATABASE_URL env var
- [x] Schema migration: services, log_entries, system_metrics, active_sessions, alerts, api_keys
- [x] Query structs for all tables
- [x] Service repository: CRUD, get_or_create, find_by_virtual_host
- [x] LogEntry repository: batch insert with noise-aware raw_line storage

## Phase 3: System Monitor (Pending)

- [ ] MetricCollector (CPU, mem, disk, net)
  - Test: Metrics collection with mocked sysinfo
- [ ] SessionTracker
  - Test: Parse who/w output
- [ ] SystemMetric repository
  - Test: Insert, time-range queries

## Phase 4: Service Tracker (Complete)

- [x] ServiceDiscoverer (systemctl parsing)
  - Test: Unit discovery with mock output, user-created vs system classification
- [x] ServiceMonitor
  - Test: Status, resource collection (ActiveState, MemoryCurrent, CPUUsageNSec, NRestart)
- [x] Service repository
  - Test: CRUD operations
- [x] JournalctlTailer (sdjournal crate)
  - Test: LiveJournal with LiveSubscription, multi-service tailing

## Phase 5: Alerting (Pending)

- [ ] AlertRules definitions
  - Test: Rule validation
- [ ] AlertEvaluator
  - Test: Threshold checks, service down detection
- [ ] Alert repository
  - Test: CRUD operations

## Phase 6: API (Pending)

- [ ] Route definitions
  - Test: Route registration
- [ ] TLS setup
  - Test: HTTPS endpoint
- [ ] API key auth middleware
  - Test: Valid/invalid keys, permissions
- [ ] Rate limiting middleware
  - Test: Limit enforcement
- [ ] Service handlers
  - Test: CRUD endpoints
- [ ] Log handlers
  - Test: Filtering queries
- [ ] Metric handlers
  - Test: Time-range queries
- [ ] Alert handlers
  - Test: Alert management
- [ ] End-to-end API tests
  - Test: Full request flow with auth

## Phase 7: Integration (Pending)

- [ ] main.rs DI wiring
  - Test: App startup/shutdown
- [ ] Graceful shutdown
  - Test: Ctrl+C handling
- [ ] Health endpoint
  - Test: Liveness check
- [ ] Full integration test suite
  - Test: End-to-end scenarios

## Commands Reference

```bash
# Development
cargo test                    # Run all tests
cargo test --lib log_scanner  # Run specific module tests
cargo clippy -- -D warnings   # Lint (warnings as errors)
cargo fmt                     # Format code
cargo build --release         # Build release binary

# Database
cargo sqlx migrate add <name> # Create migration
cargo sqlx migrate run        # Run migrations

# CI-ready
cargo fmt --check && cargo clippy -- -D warnings && cargo test
```
