import { AreaChart, BarChart, LineChart } from "@mantine/charts";
import { Card, Title } from "@mantine/core";
import type { MetricPoint } from "../../api/types";

function fmtTime(iso: string): string {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function CpuChart({ metrics }: { metrics: MetricPoint[] }) {
  return (
    <Card withBorder radius="md" p="md">
      <Title order={5} mb="sm">
        CPU %
      </Title>
      <LineChart
        h={240}
        data={metrics.map((m) => ({ timestamp: fmtTime(m.timestamp), cpu: m.cpu_percent }))}
        dataKey="timestamp"
        series={[{ name: "cpu", color: "blue.6" }]}
        curveType="monotone"
        withDots={false}
        yAxisProps={{ domain: [0, 100], tickFormatter: (v: number) => `${v}%` }}
      />
    </Card>
  );
}

export function MemoryChart({ metrics }: { metrics: MetricPoint[] }) {
  return (
    <Card withBorder radius="md" p="md">
      <Title order={5} mb="sm">
        Memory (GB)
      </Title>
      <LineChart
        h={240}
        data={metrics.map((m) => ({
          timestamp: fmtTime(m.timestamp),
          used: m.mem_used_bytes / 1e9,
          total: m.mem_total_bytes / 1e9,
        }))}
        dataKey="timestamp"
        series={[
          { name: "used", color: "violet.6" },
          { name: "total", color: "gray.4" },
        ]}
        curveType="monotone"
        withDots={false}
      />
    </Card>
  );
}

export function LoadChart({ metrics }: { metrics: MetricPoint[] }) {
  return (
    <Card withBorder radius="md" p="md">
      <Title order={5} mb="sm">
        Load average
      </Title>
      <AreaChart
        h={240}
        data={metrics.map((m) => ({
          timestamp: fmtTime(m.timestamp),
          one: m.load_1m,
          five: m.load_5m,
        }))}
        dataKey="timestamp"
        series={[
          { name: "1m", color: "teal.6" },
          { name: "5m", color: "orange.6" },
        ]}
        curveType="monotone"
        withDots={false}
      />
    </Card>
  );
}

export function DiskGauge({ metrics }: { metrics: MetricPoint[] }) {
  const last = metrics.at(-1);
  const used = last ? last.disk_used_bytes / 1e9 : 0;
  const total = last ? last.disk_total_bytes / 1e9 : 0;
  const data = [
    { part: "Used GB", used },
    { part: "Total GB", used: total },
  ];
  return (
    <Card withBorder radius="md" p="md">
      <Title order={5} mb="sm">
        Disk {total > 0 ? `— ${((100 * used) / total).toFixed(0)}% used` : "usage"}
      </Title>
      <BarChart h={240} data={data} dataKey="part" series={[{ name: "used", color: "indigo.6" }]} />
    </Card>
  );
}
