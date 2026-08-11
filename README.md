# Sentinel

Lightweight, secure server monitoring tool written in Rust.

## Features

- **Log scanning**: Tail and parse nginx access/error logs and auth logs
- **Per-vhost monitoring**: Automatic virtual host discovery from log filenames
- **Journalctl tailing**: Tail systemd service logs (e.g., Python, Bun apps)
- **Systemd service tracking**: Auto-discover and monitor user-created services
- **Threat detection**: SQL injection, XSS, path traversal, command injection, brute force, scanner UAs
- **Noise filtering**: Exclude health checks, aggregate static assets and known bots
- **File watching**: Cross-platform log tailing via `notify` (inotify/FSEvents)
- **Log rotation aware**: Handles numeric suffix rotation (e.g., `access.log.1`)
- **Postgres storage**: Batch inserts, configurable retention
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

# Run migrations
DATABASE_URL=postgresql://user:pass@localhost/sentinel cargo sqlx migrate run
```

## Configuration

Sentinel uses a YAML config file (path via `SENTINEL_CONFIG` env var):

```yaml
log_watching:
  directories:
    - path: /var/log/nginx
      pattern: "*.log"
  files:
    - /var/log/auth.log

noise_filter:
  excluded_ips:
    - 127.0.0.1
    - 10.0.0.1
  health_check_paths:
    - /health
    - /healthz

service_tracker:
  enabled: true
  poll_interval_seconds: 30
  services:
    - name: my-python-app
      log_paths:
        - /var/log/my-python-app.log

journalctl:
  enabled: true
  services:
    - my-python-app.service
    - my-bun-app.service
```

## Nginx Setup

Sentinel expects per-vhost access logs in a custom combined format.

### Log Format

Add to `/etc/nginx/nginx.conf`:

```nginx
log_format sentinel_combined
    '$remote_addr - $remote_user [$time_local] '
    '"$request" $status $body_bytes_sent '
    '"$http_referer" "$http_user_agent" '
    '"$host" $request_time';
```

### Per-Vhost Log Files

Configure each server block with its own log file:

```nginx
server {
    listen 80;
    server_name api.example.com;

    access_log /var/log/nginx/api.example.com-access.log sentinel_combined;
    error_log  /var/log/nginx/api.example.com-error.log;
}
```

### Naming Convention

- Access logs: `<vhost>-access.log` (e.g., `api.example.com-access.log`)
- Error logs: `<vhost>-error.log` (e.g., `api.example.com-error.log`)

Sentinel discovers vhosts by scanning configured directories for `*.log` files and extracts the vhost from the `$host` field in logs.

### Log Rotation

Use standard logrotate with numeric suffixes:

```
/var/log/nginx/*-access.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 $(cat /var/run/nginx.pid)
    endscript
}
```

Sentinel ignores rotated files (e.g., `*.log.1`, `*.log.2`) and auto-discovers new files.

## Systemd Service Tracking

Sentinel auto-discovers systemd services from configured paths:

- `/etc/systemd/system` — user-created (custom) services
- `/usr/lib/systemd/system` — system-provided services

For each service, it tracks via `systemctl show`:
- Active state, sub-state, load state
- Memory usage (`MemoryCurrent`)
- CPU usage (`CPUUsageNSec`)
- Restart count (`NRestart`)

## Journalctl Tailing

For services that log to journald (e.g., Python apps, Bun runtime), enable journalctl tailing:

```yaml
journalctl:
  enabled: true
  services:
    - my-python-app.service
    - my-bun-app.service
```

Sentinel runs `journalctl -f -u <service>` for each configured service and streams lines to the scanner pipeline.

## Database

Sentinel uses Postgres with sqlx. Set `DATABASE_URL` environment variable:

```bash
export DATABASE_URL="postgresql://user:pass@localhost/sentinel"
cargo sqlx migrate run
```

### Schema

- `services` — vhosts and systemd services, log paths, virtual_host
- `log_entries` — parsed log lines, linked to service, noise flag
- `system_metrics` — CPU, memory, disk, network metrics
- `active_sessions` — SSH/console sessions
- `alerts` — triggered alert rules
- `api_keys` — API authentication keys

Raw log lines are stored only for non-noise entries to save space.

## Architecture

```
src/
├── config.rs             # YAML configuration loading
├── error.rs              # Centralized error types
├── db/                   # Database layer (sqlx/Postgres)
│   ├── models.rs         # Query structs
│   ├── pool.rs           # Connection pool
│   └── repositories/     # CRUD operations
│       ├── log_entry_repo.rs
│       └── service_repo.rs
├── log_scanner/          # Log parsing, filtering, classification, tailing
│   ├── parser/           # NginxAccessParser, AuthLogParser
│   ├── filter.rs         # NoiseFilter with security detection
│   ├── classifier.rs     # Threat classification
│   ├── tailer.rs         # FileTailer with notify-based watching
│   └── scanner.rs        # Orchestrator: tail→parse→filter→classify→store
├── service_tracker/      # Systemd service tracking
│   ├── discoverer.rs     # Auto-discover services from systemd paths
│   ├── monitor.rs        # systemctl show for status and resource usage
│   └── journalctl.rs     # Tail journalctl for specific services
├── api/                  # REST API (actix-web) - in progress
├── alerting/             # Alert rules and evaluation - in progress
└── system_monitor/       # System metrics collection - in progress
```

## Documentation

- [SPEC.md](SPEC.md) — Full feature specification
- [PLAN.md](PLAN.md) — Implementation plan and phases
- [PROGRESS.md](PROGRESS.md) — Current development status
- [AGENT.md](AGENT.md) — Development guidelines and conventions

## Tech Stack

Rust 2024, tokio, actix-web, sqlx (Postgres), rustls, sysinfo, notify, crossbeam-channel

## License

MIT
