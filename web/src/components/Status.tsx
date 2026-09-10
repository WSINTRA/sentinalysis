import { Alert, Center, Loader, Stack } from "@mantine/core";
import { AuthError } from "../api/client";

/** Shared loading / error states for the data pages. */
export function PageLoader() {
  return (
    <Center mih={300}>
      <Loader />
    </Center>
  );
}

/**
 * Error state. Auth failures are handled globally: the client already
 * cleared the key and fired the lock event, so the gate takes over.
 */
export function PageError({ error }: { error: Error }) {
  return (
    <Alert color="red" title="Failed to load">
      <Stack gap={4}>{error instanceof AuthError ? "Session ended." : error.message}</Stack>
    </Alert>
  );
}
