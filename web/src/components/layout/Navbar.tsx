import { Stack, Text, UnstyledButton } from "@mantine/core";
import { IconActivity, IconListDetails, IconServer } from "@tabler/icons-react";
import type { PageId } from "./AppShell";

const NAV: Array<{
  id: PageId;
  label: string;
  icon: typeof IconActivity;
}> = [
  { id: "dashboard", label: "Dashboard", icon: IconActivity },
  { id: "events", label: "Events", icon: IconListDetails },
  { id: "servers", label: "Servers", icon: IconServer },
];

export function useTabs(
  page: PageId,
  setPage: (page: PageId) => void,
): { links: React.ReactNode; header: string } {
  const links = (
    <Stack gap={4} p="md" pt="xl">
      {NAV.map((item) => (
        <UnstyledButton
          key={item.id}
          onClick={() => setPage(item.id)}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "8px 12px",
            borderRadius: 8,
            backgroundColor: page === item.id ? "var(--mantine-color-blue-light)" : undefined,
          }}
        >
          <item.icon size={18} />
          <Text size="sm" fw={page === item.id ? 600 : 400}>
            {item.label}
          </Text>
        </UnstyledButton>
      ))}
    </Stack>
  );
  const header = NAV.find((item) => item.id === page)?.label ?? "Sentinel";
  return { links, header };
}
