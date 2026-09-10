import {
  Badge,
  Card,
  Drawer,
  Group,
  Pagination,
  Select,
  Stack,
  Table,
  Text,
  Tooltip,
} from "@mantine/core";
import { useMemo, useState } from "react";
import type { AppEvent } from "../api/types";
import { PageError, PageLoader } from "../components/Status";
import { useEvents, useSummary } from "../hooks/useHubData";

const RANGES = ["1h", "6h", "24h", "7d", "30d"];
const PAGE_SIZE = 50;

function typeColor(type: string): string {
  // Stable pseudo-color per type, from a small safe palette.
  const palette = ["blue", "grape", "teal", "orange", "cyan", "violet", "lime", "pink"];
  let hash = 0;
  for (const ch of type) hash = (hash * 31 + ch.charCodeAt(0)) % 997;
  return palette[hash % palette.length];
}

function relative(iso: string): string {
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return `${Math.floor(seconds)}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export default function EventsPage() {
  const [app, setApp] = useState<string | null>(null);
  const [type, setType] = useState<string | null>(null);
  const [range, setRange] = useState<string>("24h");
  const [page, setPage] = useState(1);

  const summary = useSummary();
  const offset = (page - 1) * PAGE_SIZE;
  const events = useEvents({
    app: app ?? undefined,
    type: type ?? undefined,
    range,
    limit: PAGE_SIZE,
    offset,
  });

  const appOptions = useMemo(() => Object.keys(summary.data?.events_by_app ?? {}), [summary.data]);
  const typeOptions = useMemo(
    () => Object.keys(summary.data?.events_by_type ?? {}),
    [summary.data],
  );

  if (events.isPending || summary.isPending) return <PageLoader />;
  if (events.isError) return <PageError error={events.error} />;
  if (summary.isError) return <PageError error={summary.error} />;

  const total = events.data.total;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <Stack gap="md">
      <Card withBorder radius="md" p="sm">
        <Group gap="sm">
          <Select
            placeholder="App"
            clearable
            data={appOptions}
            value={app}
            onChange={(v) => {
              setApp(v);
              setPage(1);
            }}
            w={220}
          />
          <Select
            placeholder="Event type"
            clearable
            data={typeOptions}
            value={type}
            onChange={(v) => {
              setType(v);
              setPage(1);
            }}
            w={220}
          />
          <Select
            placeholder="Range"
            data={RANGES}
            value={range}
            onChange={(v) => {
              setRange(v ?? "24h");
              setPage(1);
            }}
            w={130}
          />
        </Group>
      </Card>

      <EventsTable events={events.data.events} />
      <Group justify="space-between">
        <Text size="sm" c="dimmed">
          {total} event{total === 1 ? "" : "s"} in range
        </Text>
        <Pagination value={page} onChange={setPage} total={pages} size="sm" />
      </Group>
    </Stack>
  );
}

function EventsTable({ events }: { events: AppEvent[] }) {
  const [selected, setSelected] = useState<AppEvent | null>(null);

  return (
    <>
      <Table.ScrollContainer minWidth={720}>
        <Table highlightOnHover verticalSpacing="xs" fz="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th w={140}>Time</Table.Th>
              <Table.Th w={140}>App</Table.Th>
              <Table.Th w={160}>Type</Table.Th>
              <Table.Th w={120}>User</Table.Th>
              <Table.Th>Payload</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {events.length === 0 && (
              <Table.Tr>
                <Table.Td colSpan={5}>
                  <Text c="dimmed" ta="center" py="md">
                    No events match these filters.
                  </Text>
                </Table.Td>
              </Table.Tr>
            )}
            {events.map((event) => (
              <Table.Tr
                key={event.id}
                onClick={() => setSelected(event)}
                style={{ cursor: "pointer" }}
              >
                <Table.Td>
                  <Tooltip label={new Date(event.timestamp).toLocaleString()}>
                    <Text size="sm" style={{ whiteSpace: "nowrap" }}>
                      {relative(event.timestamp)}
                    </Text>
                  </Tooltip>
                </Table.Td>
                <Table.Td>
                  <Badge variant="light" color="blue" size="sm">
                    {event.app_name}
                  </Badge>
                </Table.Td>
                <Table.Td>
                  <Badge variant="light" color={typeColor(event.event_type)} size="sm">
                    {event.event_type}
                  </Badge>
                </Table.Td>
                <Table.Td>
                  {event.user_id ? (
                    <Text size="sm" style={{ wordBreak: "break-all" }}>
                      {event.user_id}
                    </Text>
                  ) : (
                    <Text size="sm" c="dimmed">
                      —
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>
                  {Object.keys(event.payload ?? {}).length === 0 ? (
                    <Text size="sm" c="dimmed">
                      —
                    </Text>
                  ) : (
                    <Text size="xs" c="dimmed" lineClamp={2}>
                      {JSON.stringify(event.payload)}
                    </Text>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      {/* Payload viewer: escaped text only — React escaping + strict CSP is
        the XSS defense; never render payloads as HTML. */}
      <Drawer
        opened={selected !== null}
        onClose={() => setSelected(null)}
        title={selected ? `${selected.app_name} · ${selected.event_type}` : ""}
        position="right"
        size="md"
      >
        {selected && (
          <Stack gap="sm">
            <Group gap="sm">
              <Badge variant="light" color={typeColor(selected.event_type)}>
                {selected.event_type}
              </Badge>
              <Text size="sm" c="dimmed">
                {new Date(selected.timestamp).toLocaleString()}
              </Text>
            </Group>
            {selected.user_id && <Text size="sm">user: {selected.user_id}</Text>}
            <Text size="sm" fw={600}>
              Payload
            </Text>
            <pre
              style={{
                fontSize: 12,
                background: "var(--mantine-color-gray-0)",
                padding: 12,
                borderRadius: 8,
                overflow: "auto",
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
              }}
            >
              {JSON.stringify(selected.payload, null, 2)}
            </pre>
          </Stack>
        )}
      </Drawer>
    </>
  );
}
