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
const getCache = new Map<string, { expiresAt: number; value: any }>();
const getInFlight = new Map<string, Promise<any>>();

const DEFAULT_API_TIMEOUT_MS = 15000;
const PUBLIC_AUTH_PATHS = new Set([
  "/api/auth/login",
  "/api/auth/refresh",
  "/api/auth/features",
  "/api/auth/otp/login",
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

function defaultGetCacheMs(path: string): number {
  if (!path.startsWith("/api/")) return 0;
  if (path.startsWith("/api/auth/")) return 0;
  if (path.startsWith("/api/overview")) return 0;
  if (path.startsWith("/api/events/")) return 0;
  if (path.startsWith("/api/ingest/storm/status")) return 0;
  if (path.startsWith("/api/alerts/recent")) return 0;
  return 8000;
}

function invalidateGetCache(prefix?: string) {
  if (!prefix) {
    getCache.clear();
    return;
  }
  for (const k of Array.from(getCache.keys())) {
    if (k.startsWith(prefix)) getCache.delete(k);
  }
}

export async function apiFetch<T>(path: string, init?: ApiRequestInit): Promise<T> {
  const isAuthEndpoint = path.startsWith("/api/auth/");
  const isPublicAuth = isAuthEndpoint && isPublicAuthEndpoint(path);

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
    const msg = (body && typeof body === "object" && body.detail) ? String(body.detail) : `HTTP ${res.status}`;
    throw makeHttpError(res.status, body, msg);
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
