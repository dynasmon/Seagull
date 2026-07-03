import { LruCache } from "@/shared/lib/lruCache";

export type HttpError = Error & {
  status: number;
  body?: any;
};

export type AuthUser = {
  id: number;
  username: string;
  role: string;
};

export type TokenOut = {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
  user: AuthUser;
};
export type AuthFeatures = {
  otp_enabled: boolean;
};

let accessToken: string | null = null;
type RefreshResult = { accessToken: string | null; user: AuthUser | null };

let refreshInFlight: Promise<RefreshResult> | null = null;
type GetCacheEntry = { expiresAt: number; value: unknown };
const GET_CACHE_MAX = 300;
const getCache = new LruCache<string, GetCacheEntry>(GET_CACHE_MAX);
const getInFlight = new Map<string, Promise<any>>();
const etagStore = new Map<string, string>();
const ETAG_STORE_MAX = 500;

const DEFAULT_API_TIMEOUT_MS = 15000;
const PUBLIC_AUTH_PATHS = new Set([
  "/api/auth/login",
  "/api/auth/refresh",
  "/api/auth/features",
  "/api/auth/otp/login",
]);
const SWR_GET_CACHE_MS = new Map<string, number>([
  ["/api/overview", 5000],
  ["/api/alerts/recent", 3000],
  ["/api/events/network/summary", 5000],
  ["/api/events/ssh/summary", 5000],
  ["/api/exposure/summary", 10000],
  ["/api/exposure/paths", 10000],
  ["/api/network-topology/summary", 10000],
  ["/api/network-topology/graph", 10000],
  ["/api/vuln/summary", 10000],
  ["/api/vuln/posture", 10000],
]);

export type ApiRequestInit = RequestInit & {
  timeoutMs?: number;
};

export type ApiGetOptions = {
  cacheMs?: number;
  force?: boolean;
  timeoutMs?: number;
  signal?: AbortSignal;
};

export function setAccessToken(token: string | null) {
  accessToken = token;
}

export function getAccessToken() {
  return accessToken;
}

function getCookie(name: string): string | null {
  const m = document.cookie.match(new RegExp(`(?:^|; )${name.replace(/([.$?*|{}()\[\]\\\/\+^])/g, "\\$1")}=([^;]*)`));
  return m ? decodeURIComponent(m[1]) : null;
}

function isAbortErrorLike(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && (error as { name?: string }).name === "AbortError");
}

export function isAbortError(error: unknown): boolean {
  return isAbortErrorLike(error);
}

function stripQuery(path: string): string {
  const value = String(path || "");
  const queryIdx = value.indexOf("?");
  return queryIdx >= 0 ? value.slice(0, queryIdx) : value;
}

function isPublicAuthEndpoint(path: string): boolean {
  return PUBLIC_AUTH_PATHS.has(stripQuery(path));
}

async function fetchWithPolicy(path: string, init?: ApiRequestInit): Promise<Response> {
  const controller = new AbortController();
  const timeoutMs = Math.max(0, init?.timeoutMs ?? DEFAULT_API_TIMEOUT_MS);
  let didTimeout = false;
  let timeoutId: number | null = null;
  let onAbort: (() => void) | null = null;

  if (init?.signal) {
    if (init.signal.aborted) controller.abort();
    else {
      onAbort = () => controller.abort();
      init.signal.addEventListener("abort", onAbort, { once: true });
    }
  }

  if (timeoutMs > 0) {
    timeoutId = window.setTimeout(() => {
      didTimeout = true;
      controller.abort();
    }, timeoutMs);
  }

  try {
    return await fetch(path, {
      ...init,
      credentials: "include",
      signal: controller.signal,
      headers: {
        ...(init?.headers || {}),
        "Accept": "application/json",
      },
    });
  } catch (error) {
    if (didTimeout) {
      const timeoutError = new Error("Request timed out");
      timeoutError.name = "TimeoutError";
      throw timeoutError;
    }
    throw error;
  } finally {
    if (timeoutId !== null) window.clearTimeout(timeoutId);
    if (init?.signal && onAbort) init.signal.removeEventListener("abort", onAbort);
  }
}

async function rawFetch(path: string, init?: ApiRequestInit): Promise<Response> {
  return fetchWithPolicy(path, {
    ...init,
    headers: {
      ...(init?.headers || {}),
      "Accept": "application/json",
    },
  });
}

async function runRefresh(): Promise<RefreshResult> {
  // If the CSRF cookie is missing, we are not in an authenticated session yet.
  // Avoid calling /auth/refresh to prevent noisy 403s on the login screen.
  const csrfCookie = getCookie("nw_csrf");
  if (!csrfCookie) {
    setAccessToken(null);
    return { accessToken: null, user: null };
  }

  if (refreshInFlight) return refreshInFlight;

  refreshInFlight = (async (): Promise<RefreshResult> => {
    try {
      // Re-read in case cookies changed while awaiting.
      const csrf = getCookie("nw_csrf") || csrfCookie;
      const res = await rawFetch("/api/auth/refresh", {
        method: "POST",
        headers: csrf ? { "X-CSRF-Token": csrf } : {},
      });
      if (!res.ok) {
        setAccessToken(null);
        return { accessToken: null, user: null };
      }
      const data = (await res.json()) as Partial<TokenOut>;
      const tok = typeof data?.access_token === "string" ? data.access_token : null;
      const user = (data as any)?.user as AuthUser | undefined;
      setAccessToken(tok);
      return { accessToken: tok, user: user ?? null };
    } catch {
      setAccessToken(null);
      return { accessToken: null, user: null };
    } finally {
      refreshInFlight = null;
    }
  })();

  return refreshInFlight;
}

async function refreshAccessToken(): Promise<string | null> {
  const r = await runRefresh();
  return r.accessToken;
}

/**
 * Boot-time session restore (refresh + user).
 *
 * IMPORTANT: requires the CSRF cookie to exist (double-submit protection).
 */
export async function refreshSession(): Promise<RefreshResult> {
  return runRefresh();
}

function makeHttpError(status: number, body: any, message: string): HttpError {
  const err = new Error(message) as HttpError;
  err.status = status;
  err.body = body;
  return err;
}

function cacheKey(path: string): string {
  return String(path || "");
}

function rememberEtag(key: string, etag: string): void {
  if (!etagStore.has(key) && etagStore.size >= ETAG_STORE_MAX) {
    const firstKey = etagStore.keys().next().value;
    if (firstKey !== undefined) {
      etagStore.delete(firstKey);
      const evicted = getCache.get(firstKey);
      if (evicted && evicted.expiresAt <= Date.now()) getCache.delete(firstKey);
    }
  }
  etagStore.set(key, etag);
}

export function defaultGetCacheMs(path: string): number {
  return SWR_GET_CACHE_MS.get(stripQuery(path)) ?? 0;
}

function invalidateGetCache(prefix?: string) {
  if (!prefix) {
    getCache.clear();
    etagStore.clear();
    return;
  }
  for (const k of Array.from(getCache.keys())) {
    if (k.startsWith(prefix)) getCache.delete(k);
  }
  for (const k of Array.from(etagStore.keys())) {
    if (k.startsWith(prefix)) etagStore.delete(k);
  }
}

export async function apiFetch<T>(path: string, init?: ApiRequestInit): Promise<T> {
  const isAuthEndpoint = path.startsWith("/api/auth/");
  const isPublicAuth = isAuthEndpoint && isPublicAuthEndpoint(path);
  const isGetRequest = init?.method === "GET" || !init?.method;

  const doFetch = async (): Promise<Response> => {
    const headers: Record<string, string> = {
      "Accept": "application/json",
    };

    // JSON convenience
    if (init?.body && !(init?.body instanceof FormData)) {
      headers["Content-Type"] = headers["Content-Type"] || "application/json";
    }

    // Attach bearer for protected endpoints
    if ((!isAuthEndpoint || !isPublicAuth) && accessToken) {
      headers["Authorization"] = `Bearer ${accessToken}`;
    }

    const cachedEtag = isGetRequest ? etagStore.get(path) : undefined;
    if (cachedEtag) {
      headers["If-None-Match"] = cachedEtag;
    }

    return fetchWithPolicy(path, {
      ...init,
      headers: {
        ...headers,
        ...(init?.headers || {}),
      },
    });
  };

  let res = await doFetch();
  if (res.status === 401 && !isPublicAuth) {
    // Attempt one refresh + retry.
    const newTok = await refreshAccessToken();
    if (newTok) {
      res = await doFetch();
    }
  }

  if (res.status === 304 && isGetRequest) {
    const cached = getCache.get(cacheKey(path));
    if (cached) {
      return cached.value as T;
    }
    // 304 without a local body (cache evicted independently): refetch unconditionally
    etagStore.delete(path);
    res = await doFetch();
  }

  let body: any = null;
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    try {
      body = await res.json();
    } catch {
      body = null;
    }
  } else {
    try {
      body = await res.text();
    } catch {
      body = null;
    }
  }

  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    if (body && typeof body === "object" && body.detail) {
      const d = body.detail;
      if (typeof d === "string") msg = d;
      else if (Array.isArray(d)) {
        const parts = (d as unknown[])
          .map((item) => (item && typeof item === "object" ? (item as Record<string, unknown>).msg ?? null : typeof item === "string" ? item : null))
          .filter((s): s is string => typeof s === "string" && s.length > 0);
        msg = parts.length ? parts.join("; ") : `HTTP ${res.status}`;
      }
    }
    throw makeHttpError(res.status, body, msg);
  }

  if (isGetRequest) {
    const newEtag = res.headers.get("ETag");
    if (newEtag) {
      rememberEtag(path, newEtag);
      const key = cacheKey(path);
      const existing = getCache.get(key);
      // seed the body for future 304s; born expired so apiGet never serves it without revalidation
      const expiresAt = existing && existing.expiresAt > Date.now() ? existing.expiresAt : Date.now();
      getCache.set(key, { expiresAt, value: body });
    }
  }

  return body as T;
}

export function apiGet<T>(path: string, opts?: ApiGetOptions): Promise<T> {
  const ms = Math.max(0, opts?.cacheMs ?? defaultGetCacheMs(path));
  const force = Boolean(opts?.force);
  const canShareInFlight = !opts?.signal && typeof opts?.timeoutMs !== "number";

  if (ms > 0 && !force) {
    const key = cacheKey(path);
    const now = Date.now();
    const cached = getCache.get(key);
    if (cached && cached.expiresAt > now) {
      return Promise.resolve(cached.value as T);
    }
    if (canShareInFlight) {
      const pending = getInFlight.get(key);
      if (pending) return pending as Promise<T>;
    }

    const p = apiFetch<T>(path, { signal: opts?.signal, timeoutMs: opts?.timeoutMs })
      .then((out) => {
        getCache.set(key, { expiresAt: Date.now() + ms, value: out });
        return out;
      })
      .finally(() => {
        getInFlight.delete(key);
      });
    if (canShareInFlight) getInFlight.set(key, p as Promise<any>);
    return p;
  }

  return apiFetch<T>(path, { signal: opts?.signal, timeoutMs: opts?.timeoutMs });
}

export function apiPost<T>(path: string, body?: any): Promise<T> {
  return apiFetch<T>(path, {
    method: "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
  }).finally(() => {
    invalidateGetCache("/api/");
  });
}

export function apiPatch<T>(path: string, body?: any): Promise<T> {
  return apiFetch<T>(path, {
    method: "PATCH",
    body: body === undefined ? undefined : JSON.stringify(body),
  }).finally(() => {
    invalidateGetCache("/api/");
  });
}

export function apiPut<T>(path: string, body?: any): Promise<T> {
  return apiFetch<T>(path, {
    method: "PUT",
    body: body === undefined ? undefined : JSON.stringify(body),
  }).finally(() => {
    invalidateGetCache("/api/");
  });
}

export function apiDelete<T>(path: string): Promise<T> {
  return apiFetch<T>(path, { method: "DELETE" }).finally(() => {
    invalidateGetCache("/api/");
  });
}

// Convenience for auth pages
export const authApi = {
  login: (username: string, password: string) => apiPost<TokenOut>("/api/auth/login", { username, password }),
  otpLogin: (token: string) => apiPost<TokenOut>("/api/auth/otp/login", { token }),
  logout: () => apiPost<void>("/api/auth/logout"),
  logoutAll: () => apiPost<void>("/api/auth/logout-all"),
  me: () => apiGet<AuthUser>("/api/auth/me"),
  features: () => apiGet<AuthFeatures>("/api/auth/features"),
  otpCreate: (payload: { label?: string; username?: string }) => apiPost<{ token: string; expires_in: number }>("/api/auth/otp/create", payload),
};
