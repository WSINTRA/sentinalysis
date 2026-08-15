# Sentinel

Lightweight, secure server monitoring tool written in Rust.

## Features

- **Log scanning**: Tail and parse nginx access logs and auth logs
- **Per-vhost monitoring**: Automatic virtual host discovery from log filenames
- **TUI**: ratatui interface with sources panel, entry list, filtering, and threat badges
- **Daemon mode**: Background scanner started on demand by the TUI (PID-file supervised)
- **Threat detection**: SQL injection, XSS, path traversal, command injection, brute force, scanner UAs
- **Noise filtering**: Health checks and static assets stored as noise, known bots excluded
- **File watching**: Cross-platform log tailing via `notify` (inotify/FSEvents)
- **Log rotation aware**: Handles numeric suffix rotation (e.g., `access.log.1`)
- **Postgres storage**: Batch inserts, retention-ready schema
- **Planned**: journalctl tailing, systemd service tracking, REST API, alerting

## Quick Start

```bash
# Build
cargo build --release

# Test
cargo test

# Lint
cargo clippy --all-targets -- -D warnings
cargo fmt

# Run migrations
DATABASE_URL=postgresql://user:pass@localhost/sentinel cargo sqlx migrate run

# Run the TUI (starts the daemon if it is not running)
DATABASE_URL=postgresql://user:pass@localhost/sentinel cargo run -- --tui

# Run the daemon in the foreground
DATABASE_URL=postgresql://user:pass@localhost/sentinel cargo run -- --daemon
```

## Configuration

Sentinel uses a YAML config file (path via `--config`, default `config.yaml`;
missing files fall back to built-in defaults):

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

Sentinel discovers vhosts by scanning configured directories for files named
`<vhost>-access.log` (matching the configured glob pattern) and ignores
rotated files. The same discovery feeds the daemon's tailer and the TUI's
sources panel.

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

## Systemd Service Tracking (planned)

Implemented in `src/service_tracker/` but not yet wired into the daemon.
Sentinel auto-discovers systemd services from configured paths:

- `/etc/systemd/system` — user-created (custom) services
- `/usr/lib/systemd/system` — system-provided services

For each service, it tracks via `systemctl show`:
- Active state, sub-state, load state
- Memory usage (`MemoryCurrent`)
- CPU usage (`CPUUsageNSec`)
- Restart count (`NRestart`)

## Journalctl Tailing (planned)

Implemented in `src/service_tracker/journalctl.rs` (via the `sdjournal`
crate) but not yet wired into the daemon. For services that log to
journald (e.g., Python apps, Bun runtime), enable journalctl tailing:

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
- `log_entries` — parsed log lines, linked to service, noise flag, threat level
- `system_metrics`, `active_sessions`, `alerts`, `api_keys` — defined for the
  planned system-monitoring, alerting, and API phases

Raw log lines are stored only for non-noise entries to save space.

## Architecture

```
src/
├── main.rs               # CLI: TUI or daemon mode
├── config.rs             # YAML configuration loading
├── error.rs              # Centralized error types
├── setup.rs              # Tracing init, config loading
├── daemon/               # Daemon mode
│   ├── process.rs        # PID file, liveness checks, child spawning
│   └── run.rs            # Tailer → scanner loop, shutdown handling
├── db/                   # Database layer (sqlx/Postgres)
│   ├── models.rs         # Row and insert models
│   ├── pool.rs           # Connection pool
│   └── repositories/     # Write, viewer query, and service repos
│       ├── log_entry_repo.rs
│       ├── log_query_repo.rs
│       └── service_repo.rs
├── log_scanner/          # Tailing, parsing, filtering, classification
│   ├── source.rs         # Source/SourceKind model, path helpers
│   ├── source_discovery.rs # Config → discovered sources
│   ├── parser/           # NginxAccessParser, AuthLogParser
│   ├── filter.rs         # NoiseFilter (health checks, assets, bots)
│   ├── classifier/       # Threat classification (patterns)
│   ├── pipeline.rs       # Per-line: parse → filter → classify
│   ├── scanner.rs        # Batching: stream → pipeline → repository
│   └── tailer/           # FileTailer (notify-based, rotation aware)
├── service_tracker/      # Systemd tracking, not yet wired
│   ├── discoverer.rs     # Auto-discover services from systemd paths
│   ├── monitor.rs        # systemctl show for status and resources
│   └── journalctl.rs     # sdjournal tailing for specific services
└── tui/                  # ratatui terminal interface
    ├── terminal.rs       # Event loop, key handling
    ├── app.rs            # Component composition root
    ├── action.rs         # Key → Action mapping
    ├── data/             # LogDataSource trait + pg/memory impls
    └── components/
        ├── log_viewer/   # Two-panel viewer (state + rendering)
        └── status_bar.rs # Key hints and transient messages
```

## Documentation

- [SPEC.md](SPEC.md) — Full feature specification
- [PLAN.md](PLAN.md) — Implementation plan and phases
- [PROGRESS.md](PROGRESS.md) — Current development status
- [AGENT.md](AGENT.md) — Development guidelines and conventions

## Tech Stack

Rust 2024, tokio, sqlx (Postgres), ratatui, crossterm, notify, sdjournal,
tracing. (actix-web, rustls, sysinfo are declared for the planned API,
alerting, and system-monitoring phases.)

## License

MIT
