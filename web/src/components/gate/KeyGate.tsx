import {
  Alert,
  Button,
  Checkbox,
  Container,
  Paper,
  PasswordInput,
  Stack,
  Text,
  Title,
} from "@mantine/core";
import { IconShieldLock } from "@tabler/icons-react";
import { type FormEvent, useState } from "react";
import { verifyKey } from "../../api/client";
import { clearKey, getKey, storeKey } from "../../api/keyStore";

type Verify = "ok" | "invalid" | "unreachable";

export function KeyGate({ onUnlocked }: { onUnlocked: () => void }) {
  const [key, setKey] = useState("");
  const [remember, setRemember] = useState(false);
  const [status, setStatus] = useState<Verify | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setStatus(null);
    const result = await verifyKey(key.trim());
    setBusy(false);
    if (result === "ok") {
      storeKey(key.trim(), remember);
      onUnlocked();
    } else {
      setStatus(result); // nothing stored on failure
    }
  };

  // A remembered key may exist while unlocked state got desynced — offer lock.
  const hasKey = getKey() !== null;

  return (
    <Container size={420} my="auto" mih="100vh" style={{ display: "grid", alignItems: "center" }}>
      <Paper withBorder shadow="md" radius="md" p="xl">
        <Stack gap="md">
          <Stack gap={4} align="center">
            <IconShieldLock size={40} />
            <Title order={2} ta="center">
              Sentinel
            </Title>
            <Text c="dimmed" ta="center" size="sm">
              Enter a dashboard API key to unlock
            </Text>
          </Stack>

          {status === "invalid" && (
            <Alert color="red" title="Invalid key">
              The hub rejected this key. It was not stored.
            </Alert>
          )}
          {status === "unreachable" && (
            <Alert color="yellow" title="Cannot reach hub">
              Check that the hub is running and reachable.
            </Alert>
          )}

          <form onSubmit={submit}>
            <Stack gap="sm">
              <PasswordInput
                label="API key"
                placeholder="snt_…"
                value={key}
                onChange={(e) => setKey(e.currentTarget.value)}
                autoComplete="off"
                required
                data-1p-ignore
              />
              <Checkbox
                label="Remember on this device"
                description="Keeps the key in this browser after the tab closes"
                checked={remember}
                onChange={(e) => setRemember(e.currentTarget.checked)}
              />
              <Button type="submit" loading={busy} disabled={key.length === 0}>
                Unlock
              </Button>
            </Stack>
          </form>

          {hasKey && (
            <Button
              variant="subtle"
              color="gray"
              onClick={() => {
                clearKey();
                setKey("");
              }}
            >
              Forget stored key
            </Button>
          )}
        </Stack>
      </Paper>
    </Container>
  );
}
