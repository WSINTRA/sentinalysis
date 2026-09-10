# WEB_UI.md — Sentinel Dashboard (React SPA)

> **Rev 2** — refactored after security audit. Fixes applied: M1 (X-API-KEY on
> every request + key-entry gate), M3 (XSS hardening), L4 (CSP + headers).
> See HUB_PLAN.md → `SECURITY_FIXES` for the full list.

## Overview

A lightweight React SPA served by the hub's actix static file handler. Shows:
- Server metrics (CPU, memory, load, disk) as time-series charts
- Active users count (24h) from app events
- Incoming events stream, filterable by app name and event type
- Connected agents/servers

## Security Model

### Key-entry gate (M1 fix)

The SPA requires a **dashboard API key** before it renders any data:

- First visit (or expired/invalid key) → full-screen "Unlock" screen: a single
  password-style input for the key (`snt_…`)
- The key is validated with a cheap authenticated call (`GET /api/v1/health`
  with the key, or `GET /api/v1/summary`); on success the dashboard unlocks
- Storage: **`sessionStorage`** by default (cleared when the tab closes — limits
  exposure if the browser is shared/compromised). A "Remember on this device"
  checkbox opts into **`localStorage`** for convenience on trusted machines
- Every API request sends `X-API-KEY: <key>` (canonical header, same as gRPC
  and the app endpoint — one header everywhere)
- Any `401`/`403` response → clear the stored key, return to the unlock screen
- The key is **never** placed in a URL (no query params, no hash fragments —
  those leak into history, referrers, and server access logs)
- The key is never rendered in the UI after entry (password-type input,
  masked; no copy of it in React state beyond the ref needed for fetch)

Because every endpoint is key-gated server-side (HUB_PLAN.md), this SPA is safe
to deploy publicly behind TLS — the Tailscale/localhost assumption is no longer
load-bearing.

### XSS hardening (M3 fix)

- **No `dangerouslySetInnerHTML` anywhere.** Log messages and event payloads are
  untrusted strings (they may contain attacker-controlled text from web requests)
- React's default escaping is the defense — keep every value as a string child
- Payload JSON viewer renders via `<pre>{JSON.stringify(payload, null, 2)}</pre>`
  (escaped text, not HTML)
- Any future rich rendering must go through a sanitizer — noted as a review gate
- CSP is set server-side (HUB_PLAN.md): `script-src 'self'` blocks inline script
  injection even if escaping is ever bypassed
- No third-party scripts/fonts — everything is self-hosted (keeps CSP strict)

## Tech Stack

| Layer | Choice |
|-------|--------|
| Build | Vite 7 |
| Framework | React 19 + TypeScript |
| UI | Mantine 9 (components, charts, notifications) |
| Charts | @mantine/charts (Recharts-based) |
| Lint/Format | Biome |
| Data fetching | TanStack Query 5 (polling) |
| Icons | @tabler/icons-react (Mantine default) |

## Project Location

```
sentinalysis/
├── web/
│   ├── package.json
│   ├── vite.config.ts
│   ├── biome.json
│   ├── tsconfig.json
│   ├── index.html
│   ├── public/
│   └── src/
│       ├── main.tsx
│       ├── App.tsx                   # key-gate routing logic
│       ├── api/
│       │   ├── client.ts             # fetch wrapper; injects X-API-KEY
│       │   ├── keyStore.ts           # sessionStorage/localStorage handling
│       │   └── types.ts
│       ├── hooks/
│       │   ├── useMetrics.ts
│       │   ├── useEvents.ts
│       │   ├── useSummary.ts
│       │   └── useServers.ts
│       ├── components/
│       │   ├── layout/
│       │   │   ├── AppShell.tsx
│       │   │   └── Navbar.tsx
│       │   ├── gate/
│       │   │   └── KeyGate.tsx       # unlock screen
│       │   ├── dashboard/
│       │   │   ├── SummaryCards.tsx
│       │   │   ├── CpuChart.tsx
│       │   │   ├── MemoryChart.tsx
│       │   │   ├── LoadChart.tsx
│       │   │   └── DiskGauge.tsx
│       │   ├── events/
│       │   │   ├── EventsTable.tsx
│       │   │   └── EventFilters.tsx
│       │   └── servers/
│       │       └── ServersTable.tsx
│       └── pages/
│           ├── Dashboard.tsx
│           ├── Events.tsx
│           └── Servers.tsx
├── src/                  # Rust (existing)
├── proto/
├── ...
```

## Pages

### Unlock (`/` — when no valid key)

`KeyGate.tsx`:
- `PasswordInput` (Mantine) — masked, no autofill (`autoComplete="off"`)
- "Remember on this device" `Checkbox`
- Submit → `GET /api/v1/summary` with the entered key:
  - `200` → store key (`sessionStorage`, or `localStorage` if remembered), render app
  - `401/403` → inline error "Invalid key", key never stored
  - network error → "Cannot reach hub" (distinguish from invalid key)
- "Lock" button in the navbar clears stored key + TanStack Query cache and
  returns to the gate (for shared machines)

### Dashboard (`/`)

**Top row — Summary Cards (4):**
- Active Users (24h)
- Total Events (24h)
- Server Status — Online/Offline badge
- Current CPU % — color (green < 60, yellow < 85, red ≥ 85)

**Middle row — charts (2 cols):** CPU % line chart + Memory line chart (24h)

**Bottom row (2 cols):** Load average area chart + Disk usage bar

Data: `GET /api/v1/summary` + `GET /api/v1/metrics?range=24h`. Poll 30s.

### Events (`/events`)

**Filters:** app name (from `events_by_app`), event type, time range (allowlist:
1h/6h/24h/7d/30d — mirrors the server-side enum, so `400`s can't happen).

**Columns:** timestamp (relative + absolute tooltip), app badge, event-type badge
(color-coded), user id (truncated), payload (expandable escaped-JSON viewer —
`<pre>` text, never HTML).

**Pagination:** "Load more" (50/page, offset-based). Poll 15s.

### Servers (`/servers`)

Columns: agent id, hostname, status badge (online if last_seen < 90s), last seen,
first seen. Data: `GET /api/v1/servers`. Poll 30s.

## API Client (`src/api/client.ts`)

```typescript
import { getKey, clearKey } from './keyStore';

const BASE = '';  // same origin (served by hub)

export class AuthError extends Error {}

async function request<T>(path: string): Promise<T> {
  const key = getKey();
  if (!key) throw new AuthError('locked');
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'X-API-KEY': key },      // canonical header — never in URLs
  });
  if (res.status === 401 || res.status === 403) {
    clearKey();                          // bad/revoked key -> back to gate
    throw new AuthError('unauthorized');
  }
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json() as Promise<T>;
}

export const api = {
  summary: () => request<Summary>('/api/v1/summary'),
  metrics: (range: string, host?: string) =>
    request<MetricsResponse>(`/api/v1/metrics?range=${range}${host ? `&host=${host}` : ''}`),
  events: (params: EventQuery) =>
    request<EventsResponse>(`/api/v1/events?${new URLSearchParams(
      Object.entries(params).filter(([, v]) => v !== undefined).map(([k, v]) => [k, String(v)])
    )}`),
  servers: () => request<ServersResponse>('/api/v1/servers'),
};
```

### Key store (`src/api/keyStore.ts`)

```typescript
const SS = 'sentinel.key';
const LS = 'sentinel.key.remember';

export function getKey(): string | null {
  return sessionStorage.getItem(SS) ?? localStorage.getItem(LS);
}
export function storeKey(key: string, remember: boolean) {
  if (remember) localStorage.setItem(LS, key);
  else sessionStorage.setItem(SS, key);
}
export function clearKey() {
  sessionStorage.removeItem(SS);
  localStorage.removeItem(LS);
  // also reset TanStack Query cache so no stale data shows on the gate screen
}
```

## TanStack Query Hooks

```typescript
export function useSummary() {
  return useQuery({ queryKey: ['summary'], queryFn: api.summary, refetchInterval: 30_000,
                    retry: (n, err) => !(err instanceof AuthError) && n < 2 });
}
export function useMetrics(range = '24h') { /* same pattern */ }
export function useEvents(params: EventQuery) { /* refetchInterval: 15_000 */ }
export function useServers() { /* refetchInterval: 30_000 */ }
```

`AuthError` short-circuits retries and surfaces a `QueryAuthErrorBoundary` that
renders `KeyGate`.

## Mantine Components Used

- `AppShell` — layout (left nav + main content)
- `PasswordInput` — key entry (masked)
- `Card`, `Badge`, `Stack`, `Grid`, `Table`, `Select`, `Button`, `Tooltip`,
  `Progress`, `Notification`
- `@mantine/charts`: `LineChart`, `AreaChart`, `ChartTooltip`, `ChartLegend`

## Styling

- Mantine default theme (light); no custom CSS files
- Dark mode: not in scope for v1

## Build & Integration

### `package.json` scripts

```json
{
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "lint": "biome check src/",
    "preview": "vite preview"
  }
}
```

### Vite config

```typescript
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://localhost:8080',
      '/v1': 'http://localhost:8080',
    },
  },
  build: { outDir: 'dist' },
});
```

Dev: `vite dev` on :5173 proxies to the hub on :8080 (key gate works in dev too).
Prod: `vite build` → `web/dist/`, served by actix at `/`.

### Cargo integration

No Rust build changes. Actix serves static files from `config.hub.spa_path` with
the `SecurityHeaders` middleware from HUB_PLAN.md (CSP `script-src 'self'`, etc.).
**Biome CI gate:** `"noDangerouslySetInnerHTML"` is an enforceable Biome lint rule
(`a11y/noDangerouslySetInnerHtml`) — enable it so M3 stays fixed by tooling, not
by convention.

### CI (later)

```yaml
- name: Build web
  working-directory: web
  run: bun install && bun run build
```

`web/dist/` ships with the deployment artifact.

## Data Types (`src/api/types.ts`)

```typescript
export interface Summary {
  active_users_24h: number;
  total_events_24h: number;
  events_by_app: Record<string, number>;
  events_by_type: Record<string, number>;
  server_online: boolean;
  current_cpu_percent: number;
  current_mem_percent: number;
}

export interface MetricPoint {
  timestamp: string;
  cpu_percent: number;
  mem_used_bytes: number;
  mem_total_bytes: number;
  load_1m: number;
  load_5m: number;
  disk_used_bytes: number;
  disk_total_bytes: number;
  net_rx_bytes_total: number;
  net_tx_bytes_total: number;
}

export interface AppEvent {
  id: string;
  app_name: string;
  event_type: string;
  user_id: string | null;
  payload: Record<string, unknown>;
  timestamp: string;
}

export interface Agent {
  agent_id: string;
  hostname: string;
  first_seen_at: string;
  last_seen_at: string;
  online: boolean;
}

export interface EventQuery {
  app?: string;
  type?: string;
  range?: string;
  limit?: number;
  offset?: number;
}
```

## Implementation Sequence

1. Scaffold: `cd web && bun create vite . --template react-ts`
2. Install: `bun add @mantine/core @mantine/charts @mantine/hooks @tanstack/react-query @tabler/icons-react`
3. Dev deps: `bun add -d biome`; configure `biome.json` (enable `a11y/noDangerouslySetInnerHtml`)
4. `src/api/keyStore.ts` + `src/api/client.ts` (X-API-KEY, AuthError) + `types.ts`
5. `KeyGate.tsx` unlock screen + App-level gate routing
6. Hooks (`useSummary`, `useMetrics`, `useEvents`, `useServers`) with AuthError retry-off
7. `AppShell` layout + navbar with "Lock" button
8. Dashboard page (cards → charts)
9. Events page (filters + escaped payload viewer)
10. Servers page
11. Test against running hub: valid key unlocks, bad key rejected, revoke mid-session
    → 401 → gate, refresh clears sessionStorage
12. `vite build` → verify actix serves it + CSP headers present

## Dev Workflow

```bash
# Terminal 1: hub
cargo run -- --hub --config config.yaml

# Terminal 2: SPA
cd web && bun dev   # http://localhost:5173, proxies /api to :8080
```

## Security Test Checklist (SPA)

- [ ] No key stored → gate renders, no API call leaks (no fetch without header)
- [ ] Invalid key → error shown, nothing stored
- [ ] Valid key → unlocks; key present in subsequent request headers only
- [ ] `sessionStorage` cleared on tab close → gate on next visit (unless remembered)
- [ ] Hub-side key revocation mid-session → next poll 401 → gate + cache cleared
- [ ] "Lock" clears both storages + query cache
- [ ] Key never appears in any URL (check history/server logs)
- [ ] Payload viewer renders `<script>alert(1)</script>` as inert text
- [ ] Biome lint forbids `dangerouslySetInnerHTML` (CI green)
- [ ] CSP response headers present (curl -I)

## Future Enhancements (not in v1)

- Real-time updates via WebSocket/SSE (instead of polling)
- Log viewer page (parsed `log_entries` browsing)
- Alert rules + notifications (CPU > 90%, threat detected)
- Dark mode
- Multi-agent comparison
- Event export (CSV)
