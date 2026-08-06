# Sentinel

Lightweight, secure server monitoring tool written in Rust.

## Features

- **Log scanning**: Tail and parse nginx access/error logs and auth logs
- **Threat detection**: SQL injection, XSS, path traversal, command injection, brute force, scanner UAs
- **Noise filtering**: Exclude health checks, aggregate static assets and known bots
- **File watching**: Cross-platform log tailing via `notify` (inotify/FSEvents)
- **Secure by default**: Localhost-only API, TLS, API key auth (planned)

## Quick Start

```bash
# Build
cargo build --release

# Test
cargo test

# Lint
cargo clippy -- -D warnings
cargo fmt
```

## Architecture

```
src/
├── error.rs              # Centralized error types
├── log_scanner/          # Log parsing, filtering, classification, tailing
│   ├── parser/           # NginxAccessParser, AuthLogParser
│   ├── filter.rs         # NoiseFilter with security detection
│   ├── classifier.rs     # Threat classification
│   └── tailer.rs         # FileTailer with notify-based watching
├── api/                  # REST API (actix-web) - in progress
├── db/                   # Database layer (sqlx/Postgres) - in progress
├── alerting/             # Alert rules and evaluation - in progress
├── system_monitor/       # System metrics collection - in progress
└── service_tracker/      # Systemd service tracking - in progress
```

## Documentation

- [SPEC.md](SPEC.md) — Full feature specification
- [PLAN.md](PLAN.md) — Implementation plan and phases
- [PROGRESS.md](PROGRESS.md) — Current development status
- [AGENT.md](AGENT.md) — Development guidelines and conventions

## Tech Stack

Rust 2024, tokio, actix-web, sqlx (Postgres), rustls, sysinfo, notify

## License

MIT
