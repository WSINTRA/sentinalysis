import { Grid, Stack, Text } from "@mantine/core";
import { CpuChart, DiskGauge, LoadChart, MemoryChart } from "../components/dashboard/Charts";
import { SummaryCards } from "../components/dashboard/SummaryCards";
import { PageError, PageLoader } from "../components/Status";
import { useMetrics, useSummary } from "../hooks/useHubData";

export default function DashboardPage() {
  const summary = useSummary();
  const metrics = useMetrics("24h");

  if (summary.isPending || metrics.isPending) return <PageLoader />;
  if (summary.isError) return <PageError error={summary.error} />;
  if (metrics.isError) return <PageError error={metrics.error} />;

  const points = metrics.data.metrics;
  return (
    <Stack gap="md">
      <SummaryCards summary={summary.data} />
      {points.length === 0 ? (
        <Text c="dimmed">No metrics yet — waiting for agent data.</Text>
      ) : (
        <Grid>
          <Grid.Col span={{ base: 12, md: 6 }}>
            <CpuChart metrics={points} />
          </Grid.Col>
          <Grid.Col span={{ base: 12, md: 6 }}>
            <MemoryChart metrics={points} />
          </Grid.Col>
          <Grid.Col span={{ base: 12, md: 6 }}>
            <LoadChart metrics={points} />
          </Grid.Col>
          <Grid.Col span={{ base: 12, md: 6 }}>
            <DiskGauge metrics={points} />
          </Grid.Col>
        </Grid>
      )}
    </Stack>
  );
}
