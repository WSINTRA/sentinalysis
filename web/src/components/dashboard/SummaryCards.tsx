import { Badge, Card, Grid, SimpleGrid, Text } from "@mantine/core";
import type { Summary } from "../../api/types";

function cpuColor(percent: number): string {
  if (percent < 60) return "green";
  if (percent < 85) return "yellow";
  return "red";
}

export function SummaryCards({ summary }: { summary: Summary }) {
  return (
    <SimpleGrid cols={{ base: 1, xs: 2, md: 4 }} spacing="md">
      <Card withBorder radius="md" padding="md">
        <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
          Active users (24h)
        </Text>
        <Text size="xl" fw={700} mt={4}>
          {summary.active_users_24h}
        </Text>
      </Card>
      <Card withBorder radius="md" padding="md">
        <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
          Events (24h)
        </Text>
        <Text size="xl" fw={700} mt={4}>
          {summary.total_events_24h}
        </Text>
      </Card>
      <Card withBorder radius="md" padding="md">
        <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
          Server status
        </Text>
        <Badge color={summary.server_online ? "green" : "gray"} mt={8}>
          {summary.server_online ? "Online" : "Offline"}
        </Badge>
      </Card>
      <Card withBorder radius="md" padding="md">
        <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
          Current CPU
        </Text>
        <Text size="xl" fw={700} mt={4} c={cpuColor(summary.current_cpu_percent)}>
          {summary.current_cpu_percent.toFixed(1)}%
        </Text>
      </Card>
    </SimpleGrid>
  );
}

export function MemorySummary({ percent }: { percent: number }) {
  return (
    <Grid.Col span={12}>
      <Text size="sm" c="dimmed">
        Memory in use: {percent.toFixed(1)}%
      </Text>
    </Grid.Col>
  );
}
