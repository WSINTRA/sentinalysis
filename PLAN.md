# PLAN.md - Sentinel Implementation Plan

## Phase 1: Foundation (Current)

- [x] Create project documentation (SPEC.md, PLAN.md, AGENT.md, PROGRESS.md)
- [x] Initialize Rust project with cargo
- [x] Configure dependencies in Cargo.toml
- [x] Git init
- [ ] Implement error types (error.rs)
  - Test: Error enum variants, Display/Debug, From conversions
- [ ] Implement configuration loading (config.rs)
  - Test: Valid YAML parsing, invalid YAML errors, defaults
- [ ] Database pool setup (db/pool.rs)
  - Test: Connection creation, health check
- [ ] SQL migrations
  - Test: Schema creation, basic CRUD

## Phase 2: Log Scanner Core

- [ ] LogParser trait definition
  - Test: Trait object behavior
- [ ] NginxAccessParser
  - Test: Combined log format parsing, edge cases, malformed lines
- [ ] NginxErrorParser
  - Test: Severity extraction, timestamp parsing
- [ ] AuthLogParser
  - Test: Login success/fail detection
- [ ] NoiseFilter
  - Test: IP matching, path regex, user-agent filtering
- [ ] Classifier
  - Test: Level assignment, security pattern detection
- [ ] FileTailer (inotify)
  - Test: File following, rotation handling
- [ ] LogEntry repository
  - Test: Insert, query by time/service/level
- [ ] Scanner orchestrator
  - Test: Full parse→filter→classify→store pipeline

## Phase 3: System Monitor

- [ ] MetricCollector (CPU, mem, disk, net)
  - Test: Metrics collection with mocked sysinfo
- [ ] SessionTracker
  - Test: Parse who/w output
- [ ] SystemMetric repository
  - Test: Insert, time-range queries

## Phase 4: Service Tracker

- [ ] ServiceDiscoverer (systemctl parsing)
  - Test: Unit discovery with mock output
- [ ] ServiceMonitor
  - Test: Status, resource collection
- [ ] Service repository
  - Test: CRUD operations

## Phase 5: Alerting

- [ ] AlertRules definitions
  - Test: Rule validation
- [ ] AlertEvaluator
  - Test: Threshold checks, service down detection
- [ ] Alert repository
  - Test: CRUD operations

## Phase 6: API

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

## Phase 7: Integration

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
