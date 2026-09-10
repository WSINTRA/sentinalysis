# SDK_PLAN.md — Agent + Event Forwarding

> **Rev 2** — refactored after security audit. Fixes applied: H1 (agent no longer
> runs as root), H2 (per-agent keys, no client identity), L2 (bounded buffer),
> plus app-side hardening. See HUB_PLAN.md → `SECURITY_FIXES` for the full list.

## Overview

Two client-side components send data to the hub:

1. **Sentinel Agent** (`sentinel --agent`) — a mode in the existing binary that runs
   on remote servers (e.g., the e-commerce VPS). Collects system metrics and Docker
   logs, forwards them via gRPC to the hub.

2. **App event forwarding** — a small change in the e-commerce app's existing
   `analytics-service.ts` to also `POST` events to the hub's REST endpoint.

## Part 1: Sentinel Agent (`sentinel --agent`)

### Purpose

Runs as a hardened, **non-root** systemd service on the e-commerce VPS. It:
- Reads system metrics (CPU, memory, disk, load, network) every 30 seconds
- Tails Docker container log files (`/var/lib/docker/containers/*/*-json.log`)
- Batches and forwards everything to the hub over gRPC

The agent is a **pure forwarder**: it holds no identity of its own beyond its API
key. The hub derives `agent_id`/`hostname` from the key row (see HUB_PLAN.md —
"Security Model"), so the agent cannot spoof another agent, and the proto carries
no identity fields at all.

### CLI

```
sentinel --agent --config agent.yaml
```

Mutually exclusive with `--daemon`, `--hub`, `--tui`.

### Agent Config (`src/config.rs` addition)

```rust
pub struct AgentConfig {
    pub enabled: bool,
    pub hub_addr: String,            // e.g. "100.x.y.z:50051" (Tailscale IP)
    pub api_key: String,             // snt_<key_id>_<secret>
    pub containers: Vec<String>,
    pub metrics_interval_secs: u64,
    pub log_batch_size: usize,
    pub log_flush_interval_secs: u64,
    pub log_buffer_max: usize,       // bounded in-memory buffer (L2 fix)
    pub connect_timeout_secs: u64,
    pub flush_timeout_secs: u64,     // final flush deadline on shutdown
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hub_addr: "127.0.0.1:50051".into(),
            api_key: String::new(),
            containers: vec!["app".into()],
            metrics_interval_secs: 30,
            log_batch_size: 100,
            log_flush_interval_secs: 5,
            log_buffer_max: 10_000,
            connect_timeout_secs: 10,
            flush_timeout_secs: 5,
        }
    }
}
```

YAML (`agent.yaml` — **chmod 0600, owned by the `sentinel` user**; it holds the API key):
```yaml
agent:
  enabled: true
  hub_addr: "100.x.y.z:50051"
  api_key: "snt_a1b2c3d4_Xk9m..."    # never log this value
  containers:
    - "app"
  metrics_interval_secs: 30
  log_batch_size: 100
  log_flush_interval_secs: 5
  log_buffer_max: 10000
```

Alternative (nicer): systemd `LoadCredential` keeps the key out of the config
entirely — see the systemd unit below.

### Module Structure

```
src/
├── agent/
│   ├── mod.rs              # pub async fn run_agent(config) -> Result<()>
│   ├── metrics.rs          # SystemMetricsCollector (sysinfo-based)
│   ├── docker_logs.rs      # DockerLogTailer (reads container log files)
│   ├── batcher.rs          # BoundedBatcher (cap + drop-oldest + dropped counter)
│   └── client.rs           # gRPC client (tonic), retry, circuit breaker
```

### System Metrics Collector (`src/agent/metrics.rs`)

Uses the `sysinfo` crate (already in deps, currently unused). **All needed sources
are world-readable** — `/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, `/proc/net/dev`,
and `statvfs` on `/` — so the collector works fully as a non-root user:

| Metric | Source | Root required? |
|---|---|---|
| CPU % | `/proc/stat` | No |
| Memory | `/proc/meminfo` | No |
| Load avg | `/proc/loadavg` | No |
| Disk | `statvfs("/")` etc. | No |
| Network | `/proc/net/dev` | No |

```rust
pub struct SystemMetricsCollector { system: System, networks: Networks }

impl SystemMetricsCollector {
    pub fn new() -> Self { /* refresh CPU, memory, disks, networks once */ }

    pub fn collect(&mut self) -> MetricPoint {
        self.system.refresh_cpu_usage();
        self.system.refresh_memory();
        self.networks.refresh(true);
        // disks via statvfs on configured mount points (default: "/")
        MetricPoint { timestamp_ms: now_millis(), cpu_percent, mem_used, mem_total,
                      disk_used, disk_total, load_1m, load_5m,
                      net_rx_bytes_total, net_tx_bytes_total }
    }
}
```

Note: network counters are cumulative since boot; the dashboard charts deltas.

Loop: `tokio::interval(metrics_interval)` → `collect()` → send to client.

### Docker Log Tailer (`src/agent/docker_logs.rs`)

Docker stores container logs at:
`/var/lib/docker/containers/<container-id>/<container-id>-json.log`

Each line is a JSON envelope:
```json
{"log":"actual log line\n","stream":"stdout","time":"2026-09-09T12:00:00.123456789Z"}
```

The tailer:
1. On startup: resolve container names to IDs + log paths by reading
   `/var/lib/docker/containers/*/config.v2.json` (parse `Name`, `LogPath`) —
   **no `docker` CLI invocation, no shell-out**, so the agent needs no docker
   group membership and executes nothing.
2. Open each log file, seek to end (only new logs)
3. Use the existing `notify` crate to watch for file modifications
4. On modification: read new bytes from the saved offset, parse each JSON line,
   strip the trailing `\n`
5. Emit `DockerLogLine { timestamp_ms, container, stream, message }`

```rust
pub struct DockerLogTailer {
    containers: HashMap<String, ContainerLog>,  // container name -> { path, offset }
    watcher: RecommendedWatcher,
    tx: mpsc::Sender<DockerLogLine>,
}

pub struct DockerLogLine {
    pub timestamp_ms: i64,
    pub container: String,
    pub stream: String,  // "stdout" | "stderr"
    pub message: String,
}
```

Uses the same `notify` crate pattern as the existing `FileTailer` in
`src/log_scanner/tailer/`. Handles rotation/truncation (if the file shrinks below
the saved offset, reset to 0 and continue).

### Bounded Batcher (`src/agent/batcher.rs`) — L2 fix

```rust
pub struct BoundedBatcher {
    buf: VecDeque<LogLine>,
    max: usize,        // config.log_buffer_max, default 10_000
    dropped: u64,      // cumulative count of dropped-oldest lines
}

impl BoundedBatcher {
    /// Push a line; if the buffer is full, drop the OLDEST line (never blocks,
    /// never grows unbounded). Increments `dropped`.
    pub fn push(&mut self, line: LogLine) { ... }

    /// Drain up to `n` lines for a flush.
    pub fn drain(&mut self, n: usize) -> Vec<LogLine> { ... }

    /// True when a drop occurred since the last report (for rate-limited logging).
    pub fn take_dropped(&mut self) -> u64 { ... }
}
```

Behavior on hub outage:
- Hub unreachable → lines accumulate up to `max`, then **oldest are dropped** and
  counted. Memory usage is bounded at `max × 16KiB` ≈ 160 MiB worst case
  (set `log_buffer_max` lower on small boxes; 5 000 is plenty).
- A warning with the dropped count is logged at most once per 60s.
- When the hub returns, the agent resumes; the dropped counter is included in a
  periodic log so gaps are visible.

### gRPC Client (`src/agent/client.rs`)

```rust
pub struct HubClient {
    client: IngestClient<Channel>,
    api_key: String,        // sent as x-api-key metadata on EVERY call
}

impl HubClient {
    pub async fn connect(hub_addr: &str, api_key: &str, timeout: Duration) -> Result<Self> { ... }
    pub async fn send_metrics(&mut self, p: &MetricPoint) -> Result<Ack> { ... }
    pub async fn send_logs(&mut self, lines: Vec<LogLine>) -> Result<Ack> { ... }
}
```

- Auth: `x-api-key` metadata header on every request (canonical header, same as REST)
- **Retry with exponential backoff**: 1s, 2s, 4s … capped at 60s, with jitter
- **Circuit breaker**: after 5 consecutive failures, stop attempting for 60s
  (prevents hammering a down hub and keeps the metrics loop cheap)
- Log batching: flush at `log_batch_size` lines or `log_flush_interval_secs`,
  whichever comes first (same pattern as the existing `Scanner`)
- **Graceful shutdown**: on SIGINT/SIGTERM, attempt one final flush with a
  `flush_timeout_secs` deadline, then exit. Lines not flushed are counted as dropped.
- The API key is loaded once at startup and never logged, never included in
  error messages.

### Agent Run Loop (`src/agent/mod.rs`)

```
run_agent(config):
    1. Parse + format-check api key (fail fast with a clear error, no network)
    2. Connect gRPC channel to hub (connect_timeout)
    3. Spawn task: metrics_loop  (interval → collect → send; circuit breaker on error)
    4. Spawn task: logs_loop     (tailer → BoundedBatcher → send; circuit breaker on error)
    5. Await SIGINT/SIGTERM
    6. On signal: cancel token → final flush (flush_timeout) → report dropped count → exit
```

No PID file (systemd manages the process). No Postgres connection (stateless forwarder).

### Systemd Unit — hardened, NON-ROOT (H1 fix)

File: `deploy/sentinel-agent.service`

```ini
[Unit]
Description=Sentinel Agent (metrics + docker log forwarder)
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=sentinel
Group=sentinel
ExecStart=/usr/local/bin/sentinel --agent --config /etc/sentinel/agent.yaml
Restart=on-failure
RestartSec=5

# ---- Hardening: filesystem ----
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict          # entire FS read-only; reads (incl. docker logs) still work
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ReadOnlyPaths=/var/lib/docker/containers

# ---- Hardening: kernel / processes ----
RestrictSUIDSGID=true
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
SystemCallArchitectures=native
CapabilityBoundingSet=        # drop ALL capabilities
AmbientCapabilities=

# ---- Hardening: network (optional; requires systemd w/ BPF support) ----
# Only allow outbound to Tailscale CGNAT range + loopback. Comment out if it
# interferes with your setup.
IPAddressDeny=any
IPAddressAllow=localhost
IPAddressAllow=100.64.0.0/10

# ---- Resource limits (agent is tiny by design) ----
LimitNOFILE=4096
MemoryMax=256M                # headroom over the bounded buffer worst case
CPUQuota=25%
TasksMax=64

[Install]
WantedBy=multi-user.target
```

### Setup — granting log access WITHOUT root (H1 fix)

**Do NOT add the `sentinel` user to the `docker` group.** Docker group membership
is root-equivalent (any member can mount the host filesystem into a container).
Instead, grant read-only ACLs on the container log tree:

```bash
# One-time provisioning (as root)
useradd -r -s /usr/sbin/nologin -c "Sentinel Agent" sentinel

# Traverse /var/lib/docker, read the container tree, inherit for new containers
setfacl -m u:sentinel:x /var/lib/docker
setfacl -R -m u:sentinel:rX /var/lib/docker/containers
setfacl -R -d -m u:sentinel:rX /var/lib/docker/containers   # default ACL -> new containers inherit

# Config with the API key: 0600, owned by sentinel
install -o sentinel -g sentinel -m 0600 agent.yaml /etc/sentinel/agent.yaml

# Install + enable
install -m 0755 target/release/sentinel /usr/local/bin/sentinel
systemctl daemon-reload && systemctl enable --now sentinel-agent
```

Notes:
- The **default ACL** (`-d`) is what makes new container log dirs readable — set it
  once, forget it.
- Docker occasionally recreates the `containers` tree on upgrade; re-run the two
  `setfacl` lines after major Docker upgrades (add to your deploy checklist).
- Verify with `sudo -u sentinel head -c 200 /var/lib/docker/containers/*/*-json.log`.

Alternative (if ACLs are not viable): run a read-only Docker-socket proxy
(e.g. `tecnativa/docker-socket-proxy` with only `/containers` allowed) and have the
agent resolve `LogPath` via the HTTP API. More moving parts — ACLs are simpler.

Secret alternative to a 0600 config file — systemd credentials:

```ini
# In the [Service] section:
LoadCredential=agent-key:/etc/sentinel/agent.key
# Agent reads the key from $CREDENTIALS_DIRECTORY/agent-key at startup;
# systemd mounts the file read-only, decoupled from agent.yaml.
```

The agent should support both: `agent.api_key` in config OR
`SENTINEL_API_KEY_FILE=/run/credentials/sentinel-agent.service/agent-key`.

## Part 2: App Event Forwarding (E-commerce)

### Change in `new-globalware`

File: `app/server/analytics/analytics-service.ts`

Rules mirrored from the hub's validation so failures fail fast client-side:
- Header: **`X-API-KEY`** (canonical; matches gRPC and the SPA)
- **No `app_name` in the body** — the hub derives it from the key
- `event_type` validated against the same allowlist before sending
- Payload serialized-size cap (4 KiB) — drop the forward (keep the local insert)
- 3s timeout so a hung hub never piles up sockets
- Circuit breaker: 5 consecutive failures → pause forwarding for 60s
- Never log the key or the full payload on failure (log event_type + status only)

```typescript
const HUB_URL = process.env.SENTINEL_HUB_URL ?? '';
const HUB_KEY = process.env.SENTINEL_API_KEY ?? '';
const ALLOWED = new Set(['user_login','user_register','cart_add','cart_remove','cart_quantity_change','checkout_start','order_placed']);

let failures = 0;
let pausedUntil = 0;

function forwardToHub(event: { event_type: string; user_id: string | null; payload: Record<string, unknown>; timestamp: string }) {
  if (!HUB_URL || !HUB_KEY) return;               // feature off — no-op
  if (!ALLOWED.has(event.event_type)) return;      // fail fast, still stored locally
  if (Date.now() < pausedUntil) return;            // circuit breaker open
  if (JSON.stringify(event.payload).length > 4096) return; // payload cap

  fetch(`${HUB_URL}/v1/events`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-KEY': HUB_KEY },
    body: JSON.stringify({ events: [event] }),
    signal: AbortSignal.timeout(3000),
    keepalive: true,
  })
    .then((res) => {
      if (res.status === 401 || res.status === 403) {
        // Bad key: stop forwarding entirely; surfacing in hub-side audit log too.
        pausedUntil = Date.now() + 15 * 60_000;
        console.error(JSON.stringify({ level: 'error', msg: 'sentinel_forward_rejected', status: res.status, event_type: event.event_type }));
      }
      failures = 0;
    })
    .catch(() => {
      failures += 1;
      if (failures >= 5) { pausedUntil = Date.now() + 60_000; failures = 0; }
    });
}
```

`recordEvent` calls both the local insert (unchanged) and `forwardToHub(...)`.
Forwarding failure NEVER affects the request path — it is fire-and-forget, exactly
like the existing local insert.

### Env Vars (docker-compose / .env on the e-commerce VPS)

```
SENTINEL_HUB_URL=http://100.x.y.z:8080
SENTINEL_API_KEY=snt_e5f6a7b8_...
```

- If either is unset/empty, forwarding is a no-op — the app works identically.
- The key is an **app-scoped key** (`--app globalware`): it can ONLY write events
  under `globalware`. Leaking it cannot read dashboard data or ingest metrics.
- **Networking note:** the app container reaches the hub's Tailscale IP through the
  host's SNAT + routing (default bridge network does outbound NAT via the host,
  which routes `100.64.0.0/10` via tailscale0). Verify once after setup:
  `docker compose exec app curl -s -o /dev/null -w '%{http_code}' http://100.x.y.z:8080/api/v1/health`
  → expect `200`. If it fails, options: run the container with `network_mode: host`
  (weigh isolation tradeoff) or add a tiny userspace forwarder.
- **PII rule:** forward only operational payloads (cart snapshot, counts). Never
  forward emails, addresses, session tokens, or payment data. The 4 KiB cap plus
  the explicit allowlist of event types enforces this structurally.

### Batching (optional, later)

For v1: fire-and-forget per event (matches the existing local-insert pattern).
If volume grows, buffer events in memory and flush every 5s or 50 events. At the
current rate (cart actions + logins) per-event is fine — each is one small POST.

### No New Package

No npm package needed — ~30 lines in the existing `analytics-service.ts`.
Bun provides `fetch` and `AbortSignal.timeout` natively.

## New Dependencies for Agent Mode

Already in Cargo.toml (currently unused, now used):
- `sysinfo` — system metrics (works non-root, see table above)
- `notify` — Docker log file watching
- `crossbeam-channel` — bridging sync notify → async tokio

New (same as hub):
- `tonic` (client feature), `prost`

## Implementation Sequence

### Agent

1. Add `AgentConfig` to `src/config.rs`
2. Implement `src/agent/metrics.rs` (sysinfo collector) — unit test with fake refresh
3. Implement `src/agent/batcher.rs` (BoundedBatcher) — pure, heavily unit-tested:
   overflow drops oldest, `dropped` counter, drain semantics
4. Implement `src/agent/docker_logs.rs` (config.v2.json discovery + notify tailer)
   — test with a temp dir simulating the Docker layout
5. Implement `src/agent/client.rs` (x-api-key, backoff + jitter, circuit breaker,
   final-flush deadline)
6. Implement `src/agent/mod.rs` (run loop, signals, dropped-count reporting)
7. Wire `--agent` flag in `src/main.rs`
8. Add `deploy/sentinel-agent.service` + provisioning script (`setfacl` steps)
9. Integration test: agent → test hub over TLS-less loopback; verify metrics +
   logs land; kill hub mid-run → verify bounded buffer + drop-oldest + recovery

### App Forwarding

1. Add `SENTINEL_HUB_URL` + `SENTINEL_API_KEY` to `.env.example` (key placeholder only)
2. Add allowlist + circuit breaker + `forwardToHub` in `analytics-service.ts`
3. Add env vars to docker-compose environment
4. Manual test: hub up → e-commerce login → event appears in hub Postgres with
   `app_name = 'globalware'` (from the key, not the request)
5. Manual test: stop hub → app keeps working, forwarding pauses (circuit breaker),
   resume → events flow again
