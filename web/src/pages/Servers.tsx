import { Badge, Card, Group, Stack, Table, Text, Tooltip } from "@mantine/core";
import { PageError, PageLoader } from "../components/Status";
import { useServers } from "../hooks/useHubData";

export default function ServersPage() {
  const servers = useServers();

  if (servers.isPending) return <PageLoader />;
  if (servers.isError) return <PageError error={servers.error} />;

  const agents = servers.data.agents;
  return (
    <Stack gap="md">
      <Card withBorder radius="md" p={0}>
        <Table.ScrollContainer minWidth={640}>
          <Table highlightOnHover verticalSpacing="xs" fz="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Agent ID</Table.Th>
                <Table.Th>Hostname</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Last seen</Table.Th>
                <Table.Th>First seen</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {agents.length === 0 && (
                <Table.Tr>
                  <Table.Td colSpan={5}>
                    <Text c="dimmed" ta="center" py="md">
                      No agents have connected yet.
                    </Text>
                  </Table.Td>
                </Table.Tr>
              )}
              {agents.map((agent) => (
                <Table.Tr key={agent.agent_id}>
                  <Table.Td>
                    <Text size="sm" ff="monospace">
                      {agent.agent_id}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{agent.hostname}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Badge color={agent.online ? "green" : "gray"} size="sm">
                      {agent.online ? "Online" : "Offline"}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Tooltip label={new Date(agent.last_seen_at).toLocaleString()}>
                      <Text size="sm" style={{ whiteSpace: "nowrap" }}>
                        {new Date(agent.last_seen_at).toLocaleString()}
                      </Text>
                    </Tooltip>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" style={{ whiteSpace: "nowrap" }}>
                      {new Date(agent.first_seen_at).toLocaleDateString()}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Card>
      <Group justify="flex-end">
        <Text size="xs" c="dimmed">
          {agents.filter((a) => a.online).length}/{agents.length} online · polls every 30s
        </Text>
      </Group>
    </Stack>
  );
}
