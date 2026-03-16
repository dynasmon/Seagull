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

let accessToken: string | null = null;
type RefreshResult = { accessToken: string | null; user: AuthUser | null };

let refreshInFlight: Promise<RefreshResult> | null = null;
const getCache = new Map<string, { expiresAt: number; value: any }>();
const getInFlight = new Map<string, Promise<any>>();

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

async function rawFetch(path: string, init?: RequestInit): Promise<Response> {
  return fetch(path, {
    ...init,
    credentials: "include",
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

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const isAuthEndpoint = path.startsWith("/api/auth/");

  const doFetch = async (): Promise<Response> => {
    const headers: Record<string, string> = {
      "Accept": "application/json",
    };

    // JSON convenience
    if (init?.body && !(init?.body instanceof FormData)) {
      headers["Content-Type"] = headers["Content-Type"] || "application/json";
    }

    // Attach bearer for protected endpoints
    if (!isAuthEndpoint && accessToken) {
      headers["Authorization"] = `Bearer ${accessToken}`;
    }

    return fetch(path, {
      ...init,
      credentials: "include",
      headers: {
        ...headers,
        ...(init?.headers || {}),
      },
    });
  };

  let res = await doFetch();
  if (res.status === 401 && !isAuthEndpoint) {
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

export function apiGet<T>(path: string, opts?: { cacheMs?: number; force?: boolean }): Promise<T> {
  const ms = Math.max(0, opts?.cacheMs ?? defaultGetCacheMs(path));
  const force = Boolean(opts?.force);

  if (ms > 0 && !force) {
    const key = cacheKey(path);
    const now = Date.now();
    const cached = getCache.get(key);
    if (cached && cached.expiresAt > now) {
      return Promise.resolve(cached.value as T);
    }
    const pending = getInFlight.get(key);
    if (pending) return pending as Promise<T>;

    const p = apiFetch<T>(path)
      .then((out) => {
        getCache.set(key, { expiresAt: Date.now() + ms, value: out });
        return out;
      })
      .finally(() => {
        getInFlight.delete(key);
      });
    getInFlight.set(key, p as Promise<any>);
    return p;
  }

  return apiFetch<T>(path);
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
  me: () => apiGet<AuthUser>("/api/auth/me"),
  otpCreate: (payload: { label?: string; username?: string }) => apiPost<{ token: string; expires_in: number }>("/api/auth/otp/create", payload),
};
