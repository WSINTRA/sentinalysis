export interface Summary {
  active_users_24h: number;
  total_events_24h: number;
  events_by_app: Record<string, number>;
  events_by_type: Record<string, number>;
  server_online: boolean;
  current_cpu_percent: number;
  current_mem_percent: number;
}

/** Mirrors the hub's `MetricPointDto` (read.rs). */
export interface MetricPoint {
  timestamp: string;
  cpu_percent: number;
  mem_used_bytes: number;
  mem_total_bytes: number;
  load_1m: number;
  load_5m: number;
  disk_used_bytes: number;
  disk_total_bytes: number;
}

export interface MetricsResponse {
  metrics: MetricPoint[];
}

export interface AppEvent {
  id: string;
  app_name: string;
  event_type: string;
  user_id: string | null;
  payload: Record<string, unknown>;
  timestamp: string;
}

export interface EventsResponse {
  events: AppEvent[];
  total: number;
}

export interface Agent {
  agent_id: string;
  hostname: string;
  first_seen_at: string;
  last_seen_at: string;
  online: boolean;
}

export interface ServersResponse {
  agents: Agent[];
}

export interface EventQuery {
  app?: string;
  type?: string;
  range?: string;
  limit?: number;
  offset?: number;
}
