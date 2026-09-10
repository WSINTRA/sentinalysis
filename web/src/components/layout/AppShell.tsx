import { AppShell, Burger, Group, Title, UnstyledButton } from "@mantine/core";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { clearKey } from "../../api/keyStore";
import DashboardPage from "../../pages/Dashboard";
import EventsPage from "../../pages/Events";
import ServersPage from "../../pages/Servers";
import { useTabs } from "./Navbar";

export type PageId = "dashboard" | "events" | "servers";

/** Left nav + header layout; `page` state is lifted here. */
export function AppShellView({ onLock }: { onLock: () => void }) {
  const [page, setPage] = useState<PageId>("dashboard");
  const [opened, setOpened] = useState(false);
  const queryClient = useQueryClient();

  const { links, header } = useTabs(page, setPage);

  const lock = () => {
    clearKey();
    queryClient.clear();
    onLock();
  };

  return (
    <AppShell
      header={{ height: 60 }}
      navbar={{ width: 250, breakpoint: "sm", collapsed: { mobile: !opened } }}
      padding="md"
    >
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between" w="100%">
          <Group>
            <Burger opened={opened} onClick={() => setOpened((v) => !v)} hiddenFrom="sm" />
            <Title order={3}>{header}</Title>
          </Group>
          <UnstyledButton onClick={lock} style={{ fontWeight: 500 }}>
            Lock
          </UnstyledButton>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar>{links}</AppShell.Navbar>

      <AppShell.Main>
        {page === "dashboard" && <DashboardPage />}
        {page === "events" && <EventsPage />}
        {page === "servers" && <ServersPage />}
      </AppShell.Main>
    </AppShell>
  );
}
