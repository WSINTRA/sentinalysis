# Sentinel

Lightweight, secure server monitoring tool written in Rust.

## Features

- **Log scanning**: Tail and parse nginx access logs and auth logs
- **Per-vhost monitoring**: Automatic virtual host discovery from log filenames
- **TUI**: ratatui interface with sources panel, entry list, filtering, and threat badges
- **Daemon mode**: Background scanner started on demand by the TUI (PID-file supervised)
- **Hub mode**: Central server — gRPC ingestion (tonic), REST API (actix), dashboard serving, API-key auth, age-based retention
- **Agent mode**: Lightweight forwarder — system metrics (sysinfo) + Docker container logs → hub over gRPC
- **Web dashboard**: React SPA with key-gate unlock, metrics, app events stream, and server list
- **Threat detection**: SQL injection, XSS, path traversal, command injection, brute force, scanner UAs
- **Noise filtering**: Health checks and static assets stored as noise, known bots excluded
- **File watching**: Cross-platform log tailing via `notify` (inotify/FSEvents)
- **Log rotation aware**: Handles numeric suffix rotation (e.g., `access.log.1`)
- **Postgres storage**: Batch inserts, retention-ready schema
- **Planned**: journalctl tailing, systemd service tracking, alerting, session tracking

## Quick Start

```bash
# Build (requires protoc — tonic-build generates gRPC types)
cargo build --release

# Test
cargo test

# Lint
cargo clippy --all-targets -- -D warnings
cargo fmt

# Run migrations (needed for TUI/daemon; the hub runs them on startup itself)
DATABASE_URL=postgresql://user:pass@localhost/sentinel cargo sqlx migrate run

# Run the TUI (starts the daemon if it is not running)
DATABASE_URL=postgresql://user:pass@localhost/sentinel cargo run -- --tui

# Run the daemon in the foreground
DATABASE_URL=postgresql://user:pass@localhost/sentinel cargo run -- --daemon

# Build the dashboard SPA (served by the hub from web/dist)
cd web && npm ci && npm run build && cd ..

# Run the hub (gRPC :50051 + REST :8080, binds 127.0.0.1 by default)
DATABASE_URL=postgresql://user:pass@localhost/sentinel cargo run -- --hub

# Manage hub API keys (the raw key is printed exactly once)
DATABASE_URL=... cargo run -- hub-key create --agent vps1
DATABASE_URL=... cargo run -- hub-key create --app shop
DATABASE_URL=... cargo run -- hub-key create --dashboard "ops team"
DATABASE_URL=... cargo run -- hub-key list
DATABASE_URL=... cargo run -- hub-key revoke <key_id>

# Run an agent that forwards metrics + Docker logs to the hub
SENTINEL_API_KEY_FILE=/etc/sentinel/agent.key cargo run -- --agent
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

hub:
  enabled: true
  grpc_host: 127.0.0.1
  grpc_port: 50051
  rest_host: 127.0.0.1
  rest_port: 8080
  spa_path: ./web/dist
  tls:
    enabled: false
    cert: /etc/sentinel/tls.crt
    key: /etc/sentinel/tls.key
  retention_days: 90            # app_events + log_entries (0 disables)
  metrics_retention_days: 30    # system_metrics (0 disables)

agent:
  enabled: true
  hub_addr: 127.0.0.1:50051
  api_key: snt_...              # or leave empty and set SENTINEL_API_KEY_FILE
  containers:
    - app
  metrics_interval_secs: 30
  log_batch_size: 100
  log_flush_interval_secs: 5
  log_buffer_max: 10000
```

The hub refuses to start if a non-loopback `grpc_host`/`rest_host` is set
without `tls.enabled` (Tailscale/CGNAT addresses are allowed with a warning,
since WireGuard already encrypts).

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
- `log_entries` — parsed log lines, linked to service, noise flag, threat
  level, `source_host` (which agent forwarded it)
- `system_metrics` — per-host CPU/memory/disk/load samples (ingested from agents)
- `agents` — connected agents (`agent_id`, hostname, first/last seen)
- `app_events` — events forwarded by web apps (app name, type, user, JSON payload)
- `api_keys` — API keys with identity binding (`key_id` lookup prefix,
  `agent_id`/`hostname` or `app_name`) and permissions
- `active_sessions`, `alerts` — defined for the planned session-tracking
  and alerting phases

Raw log lines are stored only for non-noise entries to save space.

## Architecture

```
proto/sentinel.proto      # gRPC contract (identity-free wire protocol)
migrations/               # Postgres schema (sqlx)
web/                      # React SPA dashboard (Vite)
src/
├── main.rs               # CLI: --tui / --daemon / --hub / --agent, hub-key subcommand
├── config.rs             # YAML configuration loading (incl. hub + agent sections)
├── error.rs              # Centralized error types
├── setup.rs              # Tracing init, config loading
├── daemon/               # Daemon mode
│   ├── process.rs        # PID file, liveness checks, child spawning
│   └── run.rs            # Tailer → scanner loop, shutdown handling
├── db/                   # Database layer (sqlx/Postgres)
│   ├── models.rs         # Row and insert models
│   ├── pool.rs           # Connection pool
│   └── repositories/     # Log entry/query, service, metric, agent,
│       ...               # app-event, and API-key repos
├── log_scanner/          # Tailing, parsing, filtering, classification
│   ├── source.rs         # Source/SourceKind model, path helpers
│   ├── source_discovery.rs # Config → discovered sources
│   ├── parser/           # NginxAccessParser, AuthLogParser
│   ├── filter.rs         # NoiseFilter (health checks, assets, bots)
│   ├── classifier/       # Threat classification (patterns)
│   ├── pipeline.rs       # Per-line: parse → filter → classify
│   ├── scanner.rs        # Batching: stream → pipeline → repository
│   └── tailer/           # FileTailer (notify-based, rotation aware)
├── hub/                  # Hub mode: central server
│   ├── auth.rs           # API-key auth (key_id lookup → argon2 verify)
│   ├── grpc.rs           # gRPC ingestion (metrics + Docker logs)
│   ├── rest/             # actix REST: health, event ingest, read API, headers
│   ├── keys_cli.rs       # `hub-key create/list/revoke`
│   ├── retention.rs      # Age-based deletion jobs
│   └── run_hub.rs        # Startup: migrations, gRPC + REST, SPA serving
├── agent/                # Agent mode: remote forwarder
│   ├── metrics.rs        # sysinfo CPU/mem/disk/load sampling
│   ├── docker_logs.rs    # Docker container JSON-log discovery + tailing
│   └── batcher.rs        # Bounded batch buffer → gRPC, reconnect, flush
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

- [SPEC.md](SPEC.md) — Original feature specification (pre-pivot; see PROGRESS.md)
- [PLAN.md](PLAN.md) — Implementation plan and phases
- [PROGRESS.md](PROGRESS.md) — Current development status
- [HUB_PLAN.md](HUB_PLAN.md) — Hub server design and security model
- [SDK_PLAN.md](SDK_PLAN.md) — Agent + app event forwarding design
- [WEB_UI.md](WEB_UI.md) — Dashboard SPA design
- [AGENTS.md](AGENTS.md) — Development guidelines and conventions

## Tech Stack

Rust 2024, tokio, sqlx (Postgres), tonic + prost (gRPC), actix-web (REST),
ratatui + crossterm (TUI), notify (file watching), sdjournal, sysinfo
(agent metrics), argon2 + sha2 (API keys), governor (rate limiting), tracing.
The dashboard is a React + Vite SPA in `web/`.

## License

MIT
