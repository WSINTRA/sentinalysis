import { clearKey, getKey } from "./keyStore";
import type {
  EventQuery,
  EventsResponse,
  MetricsResponse,
  ServersResponse,
  Summary,
} from "./types";

const BASE = ""; // same origin (served by the hub)

export class AuthError extends Error {}

async function request<T>(path: string): Promise<T> {
  const key = getKey();
  if (!key) throw new AuthError("locked");
  const res = await fetch(`${BASE}${path}`, {
    headers: { "X-API-KEY": key }, // canonical header — never in URLs
  });
  if (res.status === 401 || res.status === 403) {
    clearKey(); // bad/revoked key -> back to the gate
    throw new AuthError("unauthorized");
  }
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return (await res.json()) as T;
}

/** Validates a candidate key without storing it (unlock-screen call). */
export async function verifyKey(key: string): Promise<"ok" | "invalid" | "unreachable"> {
  try {
    const res = await fetch("/api/v1/summary", { headers: { "X-API-KEY": key } });
    if (res.status === 200) return "ok";
    if (res.status === 401 || res.status === 403) return "invalid";
    return "unreachable";
  } catch {
    return "unreachable";
  }
}

export const api = {
  summary: () => request<Summary>("/api/v1/summary"),
  metrics: (range: string, host?: string) =>
    request<MetricsResponse>(`/api/v1/metrics?range=${range}${host ? `&host=${host}` : ""}`),
  events: (params: EventQuery) =>
    request<EventsResponse>(
      `/api/v1/events?${new URLSearchParams(
        Object.entries(params)
          .filter(([, v]) => v !== undefined)
          .map(([k, v]) => [k, String(v)]),
      )}`,
    ),
  servers: () => request<ServersResponse>("/api/v1/servers"),
};
