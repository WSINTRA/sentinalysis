const SS = "sentinel.key";
const LS = "sentinel.key.remember";

export const LOCK_EVENT = "sentinel:lock";

export function getKey(): string | null {
  return sessionStorage.getItem(SS) ?? localStorage.getItem(LS);
}

export function storeKey(key: string, remember: boolean): void {
  if (remember) localStorage.setItem(LS, key);
  else sessionStorage.setItem(SS, key);
}

export function clearKey(): void {
  sessionStorage.removeItem(SS);
  localStorage.removeItem(LS);
  window.dispatchEvent(new Event(LOCK_EVENT));
}
