import { type UseQueryResult, useQuery } from "@tanstack/react-query";
import { AuthError, api } from "../api/client";
import type {
  Agent,
  AppEvent,
  EventQuery,
  EventsResponse,
  MetricPoint,
  MetricsResponse,
  ServersResponse,
  Summary,
} from "../api/types";

const isAuthError = (err: unknown) => err instanceof AuthError;

const noAuthRetry = (failureCount: number, error: unknown) =>
  !isAuthError(error) && failureCount < 2;

export function useSummary(): UseQueryResult<Summary, Error> {
  return useQuery<Summary, Error>({
    queryKey: ["summary"],
    queryFn: api.summary,
    refetchInterval: 30_000,
    retry: noAuthRetry,
  });
}

export function useMetrics(range = "24h"): UseQueryResult<MetricsResponse, Error> {
  return useQuery<MetricsResponse, Error>({
    queryKey: ["metrics", range],
    queryFn: () => api.metrics(range),
    refetchInterval: 30_000,
    retry: noAuthRetry,
  });
}

export type { MetricPoint };

export function useEvents(params: EventQuery): UseQueryResult<EventsResponse, Error> {
  return useQuery<EventsResponse, Error>({
    queryKey: ["events", params],
    queryFn: () => api.events(params),
    refetchInterval: 15_000,
    retry: noAuthRetry,
  });
}

export type { AppEvent };

export function useServers(): UseQueryResult<ServersResponse, Error> {
  return useQuery<ServersResponse, Error>({
    queryKey: ["servers"],
    queryFn: api.servers,
    refetchInterval: 30_000,
    retry: noAuthRetry,
  });
}

export type { Agent };
