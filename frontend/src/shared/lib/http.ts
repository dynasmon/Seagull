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

async function refreshAccessToken(): Promise<string | null> {
  if (refreshInFlight) {
    const r = await refreshInFlight;
    return r.accessToken;
  }

  refreshInFlight = (async (): Promise<RefreshResult> => {
    try {
      const csrf = getCookie("nw_csrf");
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

  const r = await refreshInFlight;
  return r.accessToken;
}

/**
 * Boot-time session restore (refresh + user).
 *
 * IMPORTANT: requires the CSRF cookie to exist (double-submit protection).
 */
export async function refreshSession(): Promise<RefreshResult> {
  if (refreshInFlight) return refreshInFlight;

  refreshInFlight = (async (): Promise<RefreshResult> => {
    try {
      const csrf = getCookie("nw_csrf");
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

function makeHttpError(status: number, body: any, message: string): HttpError {
  const err = new Error(message) as HttpError;
  err.status = status;
  err.body = body;
  return err;
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

export function apiGet<T>(path: string): Promise<T> {
  return apiFetch<T>(path);
}

export function apiPost<T>(path: string, body?: any): Promise<T> {
  return apiFetch<T>(path, {
    method: "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export function apiPatch<T>(path: string, body?: any): Promise<T> {
  return apiFetch<T>(path, {
    method: "PATCH",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export function apiPut<T>(path: string, body?: any): Promise<T> {
  return apiFetch<T>(path, {
    method: "PUT",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export function apiDelete<T>(path: string): Promise<T> {
  return apiFetch<T>(path, { method: "DELETE" });
}

// Convenience for auth pages
export const authApi = {
  login: (username: string, password: string) => apiPost<TokenOut>("/api/auth/login", { username, password }),
  otpLogin: (token: string) => apiPost<TokenOut>("/api/auth/otp/login", { token }),
  logout: () => apiPost<void>("/api/auth/logout"),
  me: () => apiGet<AuthUser>("/api/auth/me"),
  otpCreate: (payload: { label?: string; username?: string }) => apiPost<{ token: string; expires_in: number }>("/api/auth/otp/create", payload),
};
