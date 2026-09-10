# HUB_PLAN.md — Sentinel Hub Server

> **Rev 2** — refactored after security audit. See `SECURITY_FIXES` at the end for
> the full list of changes and their rationale.

## Overview

The hub is a new `--hub` mode in the existing `sentinalysis` binary. It runs on the 2GB
VPS and provides:

- **gRPC ingestion server** (tonic) — receives system metrics and Docker logs from agents
- **REST API** (actix-web) — receives app events from web apps + serves query endpoints to the SPA
- **Postgres** — persists all data
- **Static file serving** — serves the pre-built React SPA behind an API-key gate

Binds to `127.0.0.1` by default (accessed via Tailscale/SSH tunnel). The design is
**secure-by-default but deployable publicly**: every endpoint requires an `X-API-KEY`,
so exposing the hub on `0.0.0.0` behind TLS is safe.

## Security Model (read this first)

### The key IS the identity

Every request — gRPC and REST — authenticates with an `X-API-KEY`. The key row in
Postgres carries the **trusted identity** (`agent_id`, `hostname`, `app_name`) and a
**permission set**. Client-supplied identity fields were removed from the protocol
entirely: an agent cannot claim to be another agent, and an app cannot claim another
app's name. There is nothing to spoof.

### Key types and permissions

| Key type | Bound identity | Permissions | Used by |
|---|---|---|---|
| **Agent** | `agent_id`, `hostname` | `ingest:metrics`, `ingest:logs` | `sentinel --agent` |
| **App** | `app_name` | `ingest:events` | Web app event forwarding |
| **Dashboard** | — | `read:dashboard` | The React SPA |

Keys are **least-privilege and non-overlapping**: a dashboard key cannot ingest, an
agent key cannot read the dashboard, an app key cannot send metrics. A leaked
dashboard key exposes reads only; a leaked app key can only write events under that
one app's name.

### Key format (prevents brute-force CPU exhaustion)

```
snt_<key_id>_<secret>
     │        └─ 32 random bytes, base64url (43 chars) — never stored
     └─ 8 hex chars derived from SHA-256(secret) — stored in plaintext, indexed
```

**Why this matters:** argon2id verify costs ~100ms. The naive design (hash the
presented key against every row in `api_keys`) is **O(n) argon2 operations per
request** — both a performance cliff and a trivial unauthenticated CPU-exhaustion
DoS. The `key_id` prefix turns this into **one indexed lookup + one argon2 verify**.

Additional layers:
1. **Format pre-check** — reject anything not matching `^snt_[0-9a-f]{8}_[A-Za-z0-9_-]{43}$`
   *before* touching argon2. Garbage keys cost microseconds.
2. **Per-IP auth-attempt rate limit** — governor, 20 attempts/min/IP, enforced
   *before* argon2. Blocks password-spraying CPU burn.
3. **In-memory verified-key cache** — 60s TTL, keyed by `key_id`, invalidated on
   revoke. Steady-state cost is a hashmap lookup, not a hash.
4. **Failure audit log** — source IP + key_id + endpoint, rate-limited to 10/min
   to prevent log flooding.

### Transport

- **Default:** `127.0.0.1` only. Agent/app traffic rides Tailscale (WireGuard, encrypted).
- **Optional TLS:** `hub.tls.enabled` adds rustls to both tonic and actix. Required
  if you ever bind to a non-loopback, non-Tailscale interface.
- Keys travel in a header, never a URL query param (would leak into access logs).

## Architecture

```
Agent (e-commerce VPS)                    Web App (Docker container)
    │                                         │
    │ gRPC :50051                             │ REST :8080
    │  X-API-KEY: snt_a1b2c3d4_...            │  X-API-KEY: snt_e5f6a7b8_...
    │  SendMetrics(MetricPoint)               │  POST /v1/events
    │  SendLogs(LogsRequest)                  │
    │                                         │
    ▼                                         ▼
┌──────────────────────────────────────────────────────────────────────┐
│  sentinel --hub (Rust, single process)                               │
│                                                                      │
│  ┌────────────────────┐   ┌────────────────────────────────────────┐ │
│  │ tonic gRPC :50051  │   │ actix-web :8080                        │ │
│  │  AuthInterceptor   │   │  KeyAuth middleware (X-API-KEY)        │ │
│  │  RateLimitInterceptor│ │  RateLimit middleware                  │ │
│  │  Ingest service    │   │  SecurityHeaders middleware (CSP)      │ │
│  └─────────┬──────────┘   │  POST /v1/events   (ingest:events)     │ │
│            │              │  GET  /api/v1/*    (read:dashboard)    │ │
│            │              │  GET  /api/v1/health  (public)         │ │
│            │              │  static SPA        (public, gated in-app)│
│            │              └───────────────┬────────────────────────┘ │
│            ▼                              ▼                          │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  auth.rs → api_keys (key_id lookup + argon2 verify + cache)  │   │
│  │           → resolves trusted identity + permissions          │   │
│  └──────────────────────────────────────────────────────────────┘   │
│            │                                                         │
│            ▼                                                         │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Postgres (sqlx)  agents, system_metrics, log_entries,       │   │
│  │                   app_events, api_keys                       │   │
│  └──────────────────────────────────────────────────────────────┘   │
│            ▲                                                         │
│  ┌─────────┴──────────────────────┐                                  │
│  │ retention.rs — daily prune task│                                  │
│  └────────────────────────────────┘                                  │
└──────────────────────────────────────────────────────────────────────┘
```

## New Dependencies

```toml
# Cargo.toml [dependencies]
tonic = "0.12"
prost = "0.13"
tokio-stream = "0.1"
sha2 = "0.10"          # key_id derivation

# [build-dependencies]
tonic-build = "0.12"
prost-build = "0.13"
```

Already declared and now actually used: `actix-web`, `actix-tls` (TLS), `argon2`
(key hashing), `governor` (rate limiting), `sysinfo` (agent side).

## Proto Definition

File: `proto/sentinel.proto`

```protobuf
syntax = "proto3";

package sentinel.v1;

service Ingest {
  rpc SendMetrics(MetricsRequest) returns (Ack);
  rpc SendLogs(LogsRequest) returns (Ack);
}

// Identity is NOT in the message — it is derived from the authenticated
// X-API-KEY on the server side. Do not add identity fields here.
message MetricsRequest {
  MetricPoint point = 1;
}

message MetricPoint {
  int64 timestamp_ms = 1;
  double cpu_percent = 2;
  uint64 mem_used_bytes = 3;
  uint64 mem_total_bytes = 4;
  uint64 disk_used_bytes = 5;
  uint64 disk_total_bytes = 6;
  double load_1m = 7;
  double load_5m = 8;
  uint64 net_rx_bytes_total = 9;
  uint64 net_tx_bytes_total = 10;
}

message LogsRequest {
  repeated LogLine lines = 1;
}

message LogLine {
  int64 timestamp_ms = 1;
  string container = 2;   // validated: ^[A-Za-z0-9._-]{1,64}$
  string stream = 3;      // validated: "stdout" | "stderr"
  string message = 4;     // capped at 16 KiB, truncated server-side
}

message Ack {
  bool accepted = 1;
  uint32 count = 2;
}
```

`build.rs`:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(["proto/sentinel.proto"], ["proto/"])
        .unwrap();
    Ok(())
}
```

### gRPC ingestion limits

| Limit | Value | Enforced in |
|---|---|---|
| Max lines per `SendLogs` | 1000 | handler → `InvalidArgument` |
| Max `message` length | 16 KiB | handler → truncate + count |
| Max `container` length | 64 chars, charset `[A-Za-z0-9._-]` | handler → reject line |
| `stream` value | must be `stdout`/`stderr` | handler → reject line |
| Requests per key per minute | 120 | `RateLimitInterceptor` |
| Max concurrent streams | 32 | tonic `http2_keepalive` config |
| Max inbound message size | 4 MiB | tonic `max_decoding_message_size` |

## Postgres Schema (New Migration)

File: `migrations/20260909000000_hub_tables.sql`

```sql
-- Tracks connected agents. Identity originates from api_keys, never from the wire.
CREATE TABLE agents (
    agent_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- App events forwarded from web applications
CREATE TABLE app_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    user_id TEXT,
    payload JSONB NOT NULL DEFAULT '{}',
    timestamp TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_event_type CHECK (event_type ~ '^[a-z0-9_.:-]{1,64}$'),
    CONSTRAINT chk_user_id_len CHECK (user_id IS NULL OR length(user_id) <= 128),
    CONSTRAINT chk_app_name CHECK (app_name ~ '^[a-z0-9._-]{1,64}$')
);

CREATE INDEX idx_app_events_app_type ON app_events(app_name, event_type);
CREATE INDEX idx_app_events_timestamp ON app_events(timestamp DESC);
CREATE INDEX idx_app_events_user ON app_events(user_id, timestamp DESC);

-- Track which agent forwarded a log entry
ALTER TABLE log_entries ADD COLUMN source_host TEXT;
CREATE INDEX idx_log_entries_source_host ON log_entries(source_host) WHERE source_host IS NOT NULL;

-- Key identity binding: the key carries the trusted identity + permissions
ALTER TABLE api_keys ADD COLUMN key_id TEXT NOT NULL UNIQUE;
ALTER TABLE api_keys ADD COLUMN agent_id TEXT;
ALTER TABLE api_keys ADD COLUMN hostname TEXT;
ALTER TABLE api_keys ADD COLUMN app_name TEXT;
ALTER TABLE api_keys ADD COLUMN revoked_at TIMESTAMPTZ;

-- Fast lookup path for auth (avoids scanning + argon2-hashing every row)
CREATE INDEX idx_api_keys_key_id ON api_keys(key_id) WHERE revoked_at IS NULL;

-- Bind each key to exactly one role
ALTER TABLE api_keys ADD CONSTRAINT chk_api_key_role CHECK (
    (agent_id IS NOT NULL AND app_name IS NULL)
    OR (agent_id IS NULL AND app_name IS NOT NULL)
    OR (agent_id IS NULL AND app_name IS NULL)  -- dashboard key
);
```

The `CHECK` constraints are **defense in depth** — validation happens in Rust first,
but a bug in the handler cannot write malformed data.

`system_metrics` and `log_entries` already exist from the initial migration and are reused.

## Module Structure (New)

```
src/
├── hub/
│   ├── mod.rs              # pub async fn run_hub(pool, config) -> Result<()>
│   ├── grpc.rs             # tonic Ingest service impl + input validation
│   ├── interceptor.rs      # tonic AuthInterceptor + RateLimitInterceptor
│   ├── auth.rs             # key parse, key_id lookup, argon2 verify, cache, permissions
│   ├── range.rs            # MetricRange allowlist -> const SQL fragments
│   ├── validate.rs         # shared input validation (event_type, names, sizes)
│   ├── security_headers.rs # actix middleware: CSP, nosniff, X-Frame-Options
│   ├── retention.rs        # daily prune task
│   └── rest/
│       ├── mod.rs          # actix App setup, middleware chain, route registration
│       ├── events.rs       # POST /v1/events
│       ├── metrics.rs      # GET /api/v1/metrics
│       ├── app_events.rs   # GET /api/v1/events
│       ├── servers.rs      # GET /api/v1/servers
│       ├── summary.rs      # GET /api/v1/summary
│       └── health.rs       # GET /api/v1/health (public)
├── db/
│   └── repositories/
│       ├── agent_repo.rs      # upsert_agent, list_agents
│       ├── app_event_repo.rs  # insert_batch, query (validated filters)
│       └── api_key_repo.rs    # find_by_key_id, create, revoke, list, touch_last_used
```

## Auth (`src/hub/auth.rs`)

### Resolved principal

```rust
pub struct Principal {
    pub key_id: String,
    pub permissions: HashSet<Permission>,
    /// Trusted identity — from the key row, never from the request.
    pub agent_id: Option<String>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
}

pub enum Permission {
    IngestMetrics,
    IngestLogs,
    IngestEvents,
    ReadDashboard,
}
```

### Verification path

```
authenticate(raw_key: &str, ip: IpAddr) -> Result<Principal, AuthError>
  1. per-IP auth attempt rate limit (governor, 20/min)  -> AuthError::RateLimited
  2. format check: ^snt_[0-9a-f]{8}_[A-Za-z0-9_-]{43}$  -> AuthError::Malformed (no argon2)
  3. cache lookup by key_id (60s TTL)                    -> hit: return cached Principal
  4. SELECT * FROM api_keys WHERE key_id = $1 AND revoked_at IS NULL
                                                         -> none: AuthError::UnknownKey (no argon2)
  5. argon2 verify(row.hash, raw_key)                    -> fail: AuthError::BadSignature
  6. build Principal from row (permissions + identity)
  7. insert into cache; UPDATE api_keys SET last_used_at = NOW() WHERE id = $1
```

Steps 1–4 all short-circuit **before** any argon2 work, so unauthenticated traffic
cannot burn CPU.

### Authorization

```rust
principal.require(Permission::IngestMetrics)?;   // -> 403 / gRPC PermissionDenied
```

Checked in every handler. `GET /api/v1/health` is the only public route (returns
`{"status":"ok"}` and nothing else — no version, no internals).

### Key management CLI

```bash
# Agent key (identity bound at creation)
sentinel hub-key create --agent ecom-01 --hostname ecom-vps
# -> snt_a1b2c3d4_Xk9...(43 chars)   (printed ONCE, never stored)

# App key
sentinel hub-key create --app globalware

# Dashboard key (for the SPA)
sentinel hub-key create --dashboard ws-laptop

sentinel hub-key list      # shows key_id, name, role, permissions, last_used_at — never the secret
sentinel hub-key revoke <key_id>
```

Secret generation: `OsRng` → 32 bytes → base64url. `key_id` = first 8 hex chars of
`SHA-256(secret)`. Stored value = `argon2id(secret)` with default OWASP params.

`revoke` sets `revoked_at` and **evicts the key_id from the auth cache immediately**
so revocation takes effect without waiting for TTL.

## Input Validation (`src/hub/validate.rs`)

All validation happens in Rust before any DB write, and is mirrored by Postgres
`CHECK` constraints.

| Field | Rule |
|---|---|
| `event_type` | `^[a-z0-9_.:-]{1,64}$`; if `hub.allowed_event_types` is non-empty, must be in that allowlist |
| `app_name` | from key row (never the request body) |
| `user_id` | optional, ≤128 chars, no control characters |
| `payload` | JSON object, serialized ≤ 4 KiB; reject (not truncate) on overflow |
| `timestamp` | must be RFC3339; reject if > `now + 5min` or < `now - 30d` (clock-skew guard) |
| batch size | `POST /v1/events`: ≤ 500 events/request; `SendLogs`: ≤ 1000 lines/request |
| request body | actix `JsonConfig::default().limit(1024 * 1024)` — 1 MiB hard cap |
| `container` | `^[A-Za-z0-9._-]{1,64}$` |
| `stream` | exactly `stdout` or `stderr` |
| `message` | ≤ 16 KiB, truncated server-side with a `…` marker; trailing `\n` stripped |
| `limit` | 1–200, default 50 |
| `offset` | ≥ 0, capped at 100 000 |

Rejected items are counted and reported in the `Ack` (`accepted: false`) or a
`422 Unprocessable Entity` response with a per-item reason — never a silent drop.

## Range Allowlist (`src/hub/range.rs`) — SQL injection guard

The `range` query param must **never** be interpolated into SQL. It parses to a
closed enum that maps to `&'static str` fragments:

```rust
pub enum MetricRange { H1, H6, H24, D7, D30 }

impl MetricRange {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "1h" => Some(Self::H1), "6h" => Some(Self::H6), "24h" => Some(Self::H24),
            "7d" => Some(Self::D7), "30d" => Some(Self::D30), _ => None,
        }
    }
    pub fn interval(&self) -> &'static str {
        match self { H1 => "1 hour", H6 => "6 hours", H24 => "24 hours",
                     D7 => "7 days", D30 => "30 days" }
    }
    pub fn bucket(&self) -> &'static str {
        match self { H1 | H6 => "1 minute", H24 => "5 minutes",
                     D7 => "30 minutes", D30 => "2 hours" }
    }
    pub fn max_rows(&self) -> i64 { 2000 }   // hard cap on returned series length
}
```

Unknown range → `400 Bad Request`. All other query params (`app`, `type`, `host`,
`limit`, `offset`) are bound as sqlx parameters — never interpolated. The
`bucket`/`interval` values are compile-time constants, so `date_trunc($bucket, ...)`
cannot be influenced by user input.

## gRPC Server (`src/hub/grpc.rs`)

Interceptors run before every handler:

```rust
Server::builder()
    .layer(RateLimitInterceptor::new(120_per_min_per_key))
    .layer(AuthInterceptor::new(auth.clone(), Permission::IngestMetrics | Permission::IngestLogs))
    .tls_config(tls)?                      // if hub.tls.enabled
    .max_decoding_message_size(4 * 1024 * 1024)
    .add_service(IngestServer::new(ingest))
    .serve_with_incoming_shutdown(...)
```

### `SendMetrics(MetricsRequest) -> Ack`

1. `AuthInterceptor` resolves `Principal`; requires `ingest:metrics`; rejects if
   `principal.agent_id` is `None` (wrong key type) → `PermissionDenied`
2. Validate `MetricPoint` (timestamp in-range, values finite and non-negative)
3. Upsert `agents` using `principal.agent_id` / `principal.hostname` (**not** message data)
4. Insert into `system_metrics`
5. `Ack { accepted: true, count: 1 }`

### `SendLogs(LogsRequest) -> Ack`

1. Same auth; requires `ingest:logs`; rejects if `principal.agent_id` is `None`
2. Reject if `lines.len() > 1000` → `InvalidArgument`
3. Per line: validate `container`, `stream`; truncate `message` to 16 KiB, strip trailing `\n`
4. Batch-insert into `log_entries` with `source_host = principal.hostname`
5. `Ack { accepted: true, count: n }` (n = accepted lines; invalid lines are
   counted separately and logged, not silently dropped)

## REST API (`src/hub/rest/`)

Middleware chain (outermost first):

```rust
App::new()
    .app_data(web::JsonConfig::default().limit(1024 * 1024))     // 1 MiB body cap
    .wrap(SecurityHeaders)                                       // CSP etc.
    .wrap(RateLimit::new(...))                                   // governor, per key + per IP
    .wrap(KeyAuth::new(auth))                                    // X-API-KEY -> Principal
    .service(web::scope("/api/v1")
        .service(health)                                         // exempt from KeyAuth
        .service(metrics).service(app_events)
        .service(servers).service(summary))
    .service(web::scope("/v1").service(post_events))
    .default_service(files)                                      // SPA
```

**Auth header is `X-API-KEY` on every route** (gRPC and REST alike) — one header,
one mental model. `Authorization: Bearer` is also accepted for convenience but
`X-API-KEY` is canonical.

### `POST /v1/events` — requires `ingest:events`

Request (note: **no `app_name`** — it comes from the key):
```json
{
  "events": [
    {
      "event_type": "user_login",
      "user_id": "uuid-or-null",
      "payload": {},
      "timestamp": "2026-09-09T12:00:00Z"
    }
  ]
}
```

Rate limit: 100 req/min per key. Max 500 events/request. Body ≤ 1 MiB.

Response `202`:
```json
{ "accepted": 1, "rejected": 0, "errors": [] }
```

Response `422` (partial validation failure):
```json
{ "accepted": 0, "rejected": 1,
  "errors": [{ "index": 0, "reason": "event_type not in allowlist" }] }
```

### `GET /api/v1/*` — requires `read:dashboard`

All read endpoints below require the header. Without it: `401`. With an
ingest-only key: `403`.

**`GET /api/v1/metrics?range=24h&host=<hostname>`**
- `range`: allowlist only (`1h|6h|24h|7d|30d`), default `24h`; anything else → `400`
- `host`: bound as a sqlx param; must match a known agent hostname
- Returns bucketed series (`MetricRange::bucket`) capped at `max_rows`

```json
{ "metrics": [ { "timestamp": "...", "cpu_percent": 23.5, "mem_used_bytes": 0,
                 "mem_total_bytes": 0, "load_1m": 0.42, "load_5m": 0.38,
                 "disk_used_bytes": 0, "disk_total_bytes": 0,
                 "net_rx_bytes_total": 0, "net_tx_bytes_total": 0 } ] }
```

**`GET /api/v1/events?app=&type=&range=&limit=50&offset=0`**
```json
{ "events": [ { "id": "uuid", "app_name": "globalware", "event_type": "user_login",
                "user_id": "uuid", "payload": {}, "timestamp": "..." } ],
  "total": 1523 }
```

**`GET /api/v1/servers`**
```json
{ "agents": [ { "agent_id": "ecom-01", "hostname": "ecom-vps",
                "first_seen_at": "...", "last_seen_at": "...", "online": true } ] }
```
`online` = `last_seen_at` within 90s (3 missed 30s cycles).

**`GET /api/v1/summary`**
```json
{ "active_users_24h": 42, "total_events_24h": 1523,
  "events_by_app": { "globalware": 1523 },
  "events_by_type": { "user_login": 42, "cart_add": 200 },
  "server_online": true, "current_cpu_percent": 23.5, "current_mem_percent": 75.0 }
```
`active_users_24h` = `SELECT COUNT(DISTINCT user_id) FROM app_events
WHERE event_type = 'user_login' AND user_id IS NOT NULL
AND timestamp > NOW() - INTERVAL '24 hours'` (const interval, not user input).

**`GET /api/v1/health`** — public, `200 {"status":"ok"}`. Returns nothing else.

### Static Files + Security Headers

Actix serves the pre-built SPA from `config.hub.spa_path` (default `./web/dist`).
Non-`/api/*`, non-`/v1/*` routes fall through to `index.html` for SPA routing.
The static assets themselves are public (the SPA is useless without a key); the
**data** is gated by the in-app key entry.

`SecurityHeaders` middleware sets on every response:

```
Content-Security-Policy: default-src 'self'; script-src 'self';
  style-src 'self' 'unsafe-inline'; img-src 'self' data:;
  connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
```

`'unsafe-inline'` on `style-src` is required by Mantine's runtime style injection.
`script-src 'self'` blocks any injected inline script — the main XSS mitigation.

## Retention (`src/hub/retention.rs`)

Event payloads carry PII (cart contents, user IDs). A daily prune task limits blast
radius:

```yaml
hub:
  retention_days: 90        # app_events, log_entries
  metrics_retention_days: 30 # system_metrics (high volume, low long-term value)
```

Runs on a `tokio::interval(24h)` after startup. Deletes in batches of 10 000 rows
with a short sleep between batches to avoid long locks on a 2GB box. Logs the
deleted count. `retention_days: 0` disables pruning.

## Config Additions (`src/config.rs`)

```rust
pub struct HubConfig {
    pub enabled: bool,
    pub grpc_host: String,          // default "127.0.0.1"
    pub grpc_port: u16,             // default 50051
    pub rest_host: String,          // default "127.0.0.1"
    pub rest_port: u16,             // default 8080
    pub spa_path: PathBuf,          // default "./web/dist"
    pub tls: TlsConfig,
    pub allowed_event_types: Vec<String>,  // empty = allow any valid-charset type
    pub retention_days: u32,        // default 90
    pub metrics_retention_days: u32,// default 30
}

pub struct TlsConfig {
    pub enabled: bool,              // default false
    pub cert: PathBuf,
    pub key: PathBuf,
}
```

YAML:
```yaml
hub:
  enabled: true
  grpc_host: "127.0.0.1"
  grpc_port: 50051
  rest_host: "127.0.0.1"
  rest_port: 8080
  spa_path: "./web/dist"
  allowed_event_types:
    - user_login
    - user_register
    - cart_add
    - cart_remove
    - cart_quantity_change
    - checkout_start
    - order_placed
  retention_days: 90
  metrics_retention_days: 30
  tls:
    enabled: false
    cert: "/etc/sentinel/tls/cert.pem"
    key: "/etc/sentinel/tls/key.pem"
```

**Startup guard:** if `grpc_host` or `rest_host` is not loopback **and** `tls.enabled`
is false, log a loud warning at startup. This prevents an accidental plaintext
public exposure.

## Entry Point Changes (`src/main.rs`)

```rust
#[derive(Subcommand)]
enum Command {
    /// Manage hub API keys
    HubKey {
        #[command(subcommand)]
        action: HubKeyAction,
    },
}

#[derive(Subcommand)]
enum HubKeyAction {
    Create { #[arg(long)] agent: Option<String>, #[arg(long)] hostname: Option<String>,
             #[arg(long)] app: Option<String>, #[arg(long)] dashboard: Option<String> },
    List,
    Revoke { key_id: String },
}
```

Top-level flags: `--hub`, `--agent`, `--daemon`, `--tui` (mutually exclusive).

`run_hub` spawns gRPC + actix + retention as tokio tasks, awaits all, handles
SIGINT/SIGTERM (same `CancellationToken` pattern as `run_daemon`).

## Migrations on Startup

Add `sqlx::migrate!().run(&pool).await?` in both `run_hub` and `run_daemon`
startup paths. Closes the existing PROGRESS.md gap (fresh Postgres currently
requires a manual `sqlx migrate run`).

## Implementation Sequence

1. Add `tonic`, `prost`, `sha2`, `tonic-build`, `prost-build` to Cargo.toml
2. Create `proto/sentinel.proto` + `build.rs`
3. Add `HubConfig` + `TlsConfig` to `src/config.rs`; add loopback/TLS startup guard
4. Add migration `20260909000000_hub_tables.sql`
5. Implement `src/hub/validate.rs` + `src/hub/range.rs` (pure, unit-testable — do these first)
6. Implement `src/db/repositories/api_key_repo.rs`
7. Implement `src/hub/auth.rs` (key parse → key_id lookup → argon2 → cache → Principal)
8. Implement `hub-key` CLI (create/list/revoke)
9. Implement `src/hub/interceptor.rs` (auth + rate limit)
10. Implement `src/hub/grpc.rs`
11. Implement `src/hub/security_headers.rs`
12. Implement `src/hub/rest/` (health → events → metrics → app_events → servers → summary)
13. Implement `src/hub/retention.rs`
14. Implement `src/hub/mod.rs`; wire `--hub` in `main.rs`
15. Add `sqlx::migrate!().run()` on startup
16. Add optional TLS to tonic + actix
17. **Security tests** (see below)
18. Integration tests: mock agent sends metrics/logs; POST /v1/events

### Security test checklist

- [ ] Malformed key (bad prefix, wrong length) → rejected without argon2 (assert timing/counters)
- [ ] Valid `key_id`, wrong secret → `401`, audit log written
- [ ] Revoked key → `401` immediately (cache eviction verified)
- [ ] Dashboard key on `POST /v1/events` → `403`
- [ ] Agent key on `GET /api/v1/summary` → `403`
- [ ] App key on `SendMetrics` → `PermissionDenied`
- [ ] 21 bad keys from one IP in a minute → `429` on the 21st
- [ ] `?range=1h;DROP TABLE agents` → `400`, tables intact
- [ ] `?range=99999d` → `400`
- [ ] `event_type` = `<script>alert(1)</script>` → `422`
- [ ] `event_type` = 5000 chars → `422`
- [ ] `payload` = 100 KiB → `422`
- [ ] Batch of 10 000 events → `422` (over 500 cap)
- [ ] Body of 5 MiB → `413`
- [ ] `app_name` in request body is ignored; stored value equals key's `app_name`
- [ ] `timestamp` 1 year in the future → `422`
- [ ] `message` of 100 KiB truncated to 16 KiB
- [ ] CSP + nosniff + X-Frame-Options present on all responses
- [ ] Non-loopback bind without TLS logs a warning
- [ ] Retention prunes rows older than `retention_days`

## Resource Budget (2GB VPS)

| Component | RAM (est.) |
|-----------|------------|
| Postgres 16 (`shared_buffers=256MB`) | 300–400 MB |
| Sentinel hub (Rust, tonic + actix + auth cache) | 60–120 MB |
| OS + kernel + Tailscale | 300 MB |
| **Total** | **~660–820 MB** |

Comfortably within 2GB. The verified-key cache is bounded (max 1000 entries, LRU).

---

## SECURITY_FIXES (Rev 1 → Rev 2)

| # | Sev | Finding | Fix |
|---|-----|---------|-----|
| H1 | High | Agent ran as root | Non-root `sentinel` user + `docker` group + ACLs (see SDK_PLAN.md) |
| H2 | High | Shared key; client-supplied `agent_id`/`hostname`/`app_name` spoofable | Per-agent keys; identity bound to the key row; **identity fields removed from the proto and the POST body** — nothing left to spoof |
| H3 | High | No input validation on `POST /v1/events` | `validate.rs`: event_type charset+length (+optional allowlist), 4 KiB payload cap, 500-event batch cap, 1 MiB body cap, timestamp skew guard, Postgres `CHECK` constraints |
| **H4** | **High** | **Auth was O(n) argon2 per request** — unauthenticated CPU-exhaustion DoS | `snt_<key_id>_<secret>` format → indexed `key_id` lookup → **one** argon2 verify. Plus format pre-check, per-IP attempt limit, and a 60s verified-key cache |
| M1 | Medium | `GET /api/v1/*` unauthenticated (Tailscale-only trust) | **`X-API-KEY` required on every route** (gRPC + REST). New `read:dashboard` permission. SPA has a key-entry gate, so the hub is safe to expose publicly |
| M2 | Medium | `range` param interpolated into SQL `INTERVAL` | `MetricRange` closed enum → `&'static str` fragments; unknown → `400`. All other params bound via sqlx |
| M3 | Medium | Stored XSS via log/event content in the SPA | CSP `script-src 'self'` (blocks inline scripts), React default escaping, explicit ban on `dangerouslySetInnerHTML` (see WEB_UI.md) |
| M4 | Medium | No rate limiting on gRPC | `RateLimitInterceptor`, 120 req/min/key; plus batch-size and message-size caps |
| L1 | Low | No TLS; plaintext keys if misconfigured | Optional rustls on tonic + actix; **startup warning when binding non-loopback without TLS** |
| L2 | Low | Unbounded agent buffer on hub outage | Bounded buffer + drop-oldest + dropped-counter (see SDK_PLAN.md) |
| L3 | Low | No PII retention policy | `retention.rs` daily prune: 90d events/logs, 30d metrics, batched deletes |
| L4 | Low | No CSP / no hardening headers on the SPA origin | `SecurityHeaders` middleware: CSP, nosniff, `X-Frame-Options: DENY`, `Referrer-Policy`, COOP |
| + | New | Secrets visible in key listing | `hub-key list` shows `key_id` + metadata only; secret printed exactly once at creation |
| + | New | Revocation delayed by cache TTL | `hub-key revoke` evicts the cache entry immediately |
| + | New | Silent data loss on validation failure | `Ack`/`422` report `rejected` count + per-item reasons |
