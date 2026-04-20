const ROUTE_LOAD_RECOVERY_KEY = "seagull:route-load-recovery:v1";
const ROUTE_LOAD_RECOVERY_WINDOW_MS = 60_000;

type StorageLike = {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
};

type RecoveryAttemptRecord = {
  path: string;
  ts: number;
};

function extractErrorName(error: unknown): string {
  if (!error || typeof error !== "object") return "";
  return String((error as { name?: unknown }).name ?? "").trim();
}

function extractErrorMessage(error: unknown): string {
  if (error instanceof Error) return String(error.message || "").trim();
  if (typeof error === "string") return error.trim();
  if (error && typeof error === "object") {
    return String((error as { message?: unknown }).message ?? "").trim();
  }
  return "";
}

function readRecoveryAttempt(storage: StorageLike): RecoveryAttemptRecord | null {
  try {
    const raw = storage.getItem(ROUTE_LOAD_RECOVERY_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<RecoveryAttemptRecord>;
    const path = String(parsed.path || "").trim();
    const ts = Number(parsed.ts || 0);
    if (!path || !Number.isFinite(ts) || ts <= 0) return null;
    return { path, ts };
  } catch {
    return null;
  }
}

export function isRecoverableRouteLoadError(error: unknown): boolean {
  const name = extractErrorName(error).toLowerCase();
  const message = extractErrorMessage(error).toLowerCase();
  const hay = `${name} ${message}`.trim();

  return [
    "chunkloaderror",
    "failed to fetch dynamically imported module",
    "error loading dynamically imported module",
    "importing a module script failed",
    "loading chunk",
    "css_chunk_load_failed",
    "unable to preload css",
  ].some((token) => hay.includes(token));
}

export function shouldAttemptRouteLoadRecovery(
  currentPath: string,
  opts: {
    storage: StorageLike;
    nowMs?: number;
  },
): boolean {
  const path = String(currentPath || "").trim() || "/";
  const nowMs = Math.max(0, Number(opts.nowMs ?? Date.now()) || 0);
  const previous = readRecoveryAttempt(opts.storage);

  if (
    previous &&
    previous.path === path &&
    (nowMs - previous.ts) < ROUTE_LOAD_RECOVERY_WINDOW_MS
  ) {
    return false;
  }

  opts.storage.setItem(
    ROUTE_LOAD_RECOVERY_KEY,
    JSON.stringify({ path, ts: nowMs }),
  );
  return true;
}

export function attemptRouteLoadRecovery(
  currentPath: string,
  opts?: {
    storage?: StorageLike;
    nowMs?: number;
    reload?: () => void;
  },
): boolean {
  const storage =
    opts?.storage ??
    (typeof window !== "undefined" ? window.sessionStorage : null);
  if (!storage) return false;

  const shouldReload = shouldAttemptRouteLoadRecovery(currentPath, {
    storage,
    nowMs: opts?.nowMs,
  });
  if (!shouldReload) return false;

  const reload = opts?.reload ?? (() => window.location.reload());
  reload();
  return true;
}

let recoveryHandlersInstalled = false;

export function installRouteLoadRecoveryHandlers(): void {
  if (recoveryHandlersInstalled || typeof window === "undefined") return;
  recoveryHandlersInstalled = true;

  const recover = (reason: unknown, preventDefault?: () => void) => {
    if (!isRecoverableRouteLoadError(reason)) return;
    preventDefault?.();
    const path = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    attemptRouteLoadRecovery(path);
  };

  window.addEventListener("vite:preloadError", (event) => {
    const preloadEvent = event as Event & { payload?: unknown; preventDefault?: () => void };
    recover(preloadEvent.payload ?? preloadEvent, () => preloadEvent.preventDefault?.());
  });

  window.addEventListener("unhandledrejection", (event) => {
    recover(event.reason, () => event.preventDefault());
  });
}
