# SPEC.md - Sentinel Server Monitor

## Overview

Sentinel is a lightweight, secure server monitoring application written in Rust. It monitors system resources, parses and analyzes logs (nginx, auth), tracks systemd services, detects anomalies, and exposes a secure API.

## Goals

- Single binary, minimal dependencies
- Low resource footprint (~100MB RAM, <5% CPU)
- Secure by default (localhost binding, TLS, API key auth)
- Per-service/per-vhost log correlation
- Configurable noise filtering
- TDD-driven development

## Non-Goals (v1)

- Web UI (API only)
- Multi-server aggregation
- mTLS (TLS + API key only for v1)
- Plugin system

## Core Features

### 1. Log Scanning

- Tail configured log files (nginx access/error, auth.log)
- Parse structured entries using format-specific parsers
- Filter noise (health checks, static assets, known bots)
- Classify entries: info/warn/error/security
- Store parsed entries in Postgres
- Support per-vhost grouping for nginx

**Parsers:**
- Nginx combined log format
- Nginx error log format
- Syslog format (auth.log)

**Noise filters (configurable):**
- IP-based exclusion (health checks)
- Path regex matching (static assets)
- User-agent matching (known bots)

**Security detection:**
- SQL injection patterns
- Path traversal attempts
- Brute force login detection
- Scanner/reconnaissance patterns

### 2. System Monitoring

- CPU usage (total, per-core)
- Memory usage (used, free, cached, swap)
- Disk usage per mount point
- Network I/O per interface
- Load average
- Collection interval: 30 seconds

### 3. Session Tracking

- Active SSH/console sessions
- Login duration, source IP
- Correlation with auth.log

### 4. Service Tracking

- Auto-discover user-created systemd services
- Status, restart count, resource usage
- Per-service log association
- Parse via `systemctl` commands

### 5. Alerting

- Configurable rules (error rate, service down, disk full)
- Store alerts in database
- Webhook notifications (future: Slack, email)

### 6. API

- actix-web based REST API
- Bind: 127.0.0.1:8443 (localhost only)
- TLS with self-signed or Let's Encrypt certs
- API key authentication (Argon2 hashed)
- Rate limiting per key

**Endpoints:**
```
GET  /api/v1/health
GET  /api/v1/services
GET  /api/v1/services/{id}
GET  /api/v1/services/{id}/logs
GET  /api/v1/metrics/system
GET  /api/v1/metrics/services/{id}
GET  /api/v1/sessions/active
GET  /api/v1/alerts
POST /api/v1/alerts/{id}/resolve
GET  /api/v1/config
PUT  /api/v1/config
```

## Architecture

```
main.rs (DI wiring)
├── Config
├── DbPool
├── LogScanner
│   ├── FileTailer (inotify)
│   ├── LogParser (trait-based)
│   ├── NoiseFilter
│   └── Classifier
├── SystemMonitor
│   ├── MetricCollector
│   └── SessionTracker
├── ServiceTracker
│   ├── Discoverer
│   └── Monitor
├── AlertEngine
│   ├── RuleEvaluator
│   └── Notifier
└── ApiServer (actix-web)
    ├── Routes
    ├── Middleware (TLS, Auth, RateLimit)
    └── Handlers
```

## Technology Stack

| Component | Crate | Version |
|-----------|-------|---------|
| Web framework | actix-web | 4.x |
| Async runtime | tokio | 1.x |
| Serialization | serde + serde_json | 1.x |
| Config | serde_yaml | 0.9.x |
| Database | sqlx (postgres, runtime-tokio-rustls) | 0.8.x |
| System info | sysinfo | 0.33.x |
| Log parsing | regex | 1.x |
| File watching | inotify | 0.11.x |
| Dates | chrono | 0.4.x |
| Logging | tracing + tracing-subscriber | 0.1.x |
| Error handling | thiserror | 2.x |
| Testing | rstest, proptest | latest |
| Argon2 hashing | argon2 | 0.5.x |
| TLS | rustls | 0.23.x |

## Database Schema (Postgres)

- services (id, name, unit_type, log_paths, virtual_host, created_at)
- log_entries (id, service_id, timestamp, level, message, raw_line, client_ip, request_path, status_code, response_time_ms, is_noise, noise_reason, created_at)
- system_metrics (id, timestamp, cpu_usage_percent, memory_used_bytes, memory_total_bytes, disk_used_bytes, disk_total_bytes, load_avg_1m, load_avg_5m, network_rx_bytes, network_tx_bytes)
- active_sessions (id, user, terminal, source_ip, login_time, idle_seconds, pid)
- alerts (id, service_id, severity, title, description, resolved, created_at, resolved_at)
- api_keys (id, name, hash, permissions, created_at, last_used_at)

## Configuration Format (YAML)

See example in PLAN.md.

## Security Requirements

- Run as non-root with minimal capabilities
- Localhost-only API binding
- TLS encryption (no plaintext)
- API key auth with hashed keys
- No shell command execution (except controlled systemctl calls)
- Audit logging for API access
- Read-only access to monitored logs

## Development Standards

- TDD: tests before implementation
- rustfmt on every commit
- clippy warnings = errors
- Module-based organization with clear boundaries
- Trait-based dependency injection
- Comprehensive error types (no unwrap() in production code)
- Documentation comments on public APIs
