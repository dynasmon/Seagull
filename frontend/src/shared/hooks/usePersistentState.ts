import { useEffect, useState, type Dispatch, type SetStateAction } from "react";

export function loadPersistentState<T>(
  key: string,
  fallback: T,
  sanitize: (raw: unknown) => T
): T {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    return sanitize(JSON.parse(raw));
  } catch {
    return fallback;
  }
}

export function usePersistentState<T>(
  key: string,
  fallback: T,
  sanitize: (raw: unknown) => T
): [T, Dispatch<SetStateAction<T>>] {
  const [value, setValue] = useState<T>(() => loadPersistentState(key, fallback, sanitize));

  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch {
      // ignore storage failures
    }
  }, [key, value]);

  return [value, setValue];
}
