import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { getKey, LOCK_EVENT } from "./api/keyStore";
import { KeyGate } from "./components/gate/KeyGate";
import { AppShellView } from "./components/layout/AppShell";

export default function App() {
  const [unlocked, setUnlocked] = useState(() => getKey() !== null);
  const queryClient = useQueryClient();

  useEffect(() => {
    const lock = () => {
      setUnlocked(false);
      queryClient.clear(); // no stale data on the gate screen
    };
    window.addEventListener(LOCK_EVENT, lock);
    return () => window.removeEventListener(LOCK_EVENT, lock);
  }, [queryClient]);

  if (!unlocked) {
    return <KeyGate onUnlocked={() => setUnlocked(true)} />;
  }
  return <AppShellView onLock={() => setUnlocked(false)} />;
}
