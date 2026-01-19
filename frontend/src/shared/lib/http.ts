export async function apiGet<T>(path: string, init?: RequestInit): Promise<T> {
  const token = localStorage.getItem("netwatch_admin_token") || "";
  const headers = new Headers(init?.headers || {});
  if (token) headers.set("X-Admin-Token", token);

  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    const msg = await res.text().catch(() => "");
    throw new Error(`HTTP ${res.status} ${res.statusText}${msg ? `: ${msg}` : ""}`);
  }
  return (await res.json()) as T;
}

type ApiError = Error & {
  status?: number;
  statusText?: string;
  body?: string;
};

async function readErrorBody(res: Response): Promise<string> {
  try {
    return await res.text();
  } catch {
    return "";
  }
}

/**
 * Minimal JSON request helper for the portal.
 * - Always attaches X-Admin-Token when present.
 * - Throws a typed Error with HTTP status and body.
 */
export async function apiJson<T>(
  path: string,
  opts: {
    method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
    body?: any;
    init?: RequestInit;
    /** If true, don't attempt to parse JSON and return void. */
    expectEmpty?: boolean;
  } = {}
): Promise<T> {
  const token = localStorage.getItem("netwatch_admin_token") || "";
  const headers = new Headers(opts.init?.headers || {});
  if (token) headers.set("X-Admin-Token", token);

  const method = opts.method || "GET";
  let body: BodyInit | undefined = undefined;

  if (opts.body !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(opts.body);
  }

  const res = await fetch(path, {
    ...opts.init,
    method,
    headers,
    body
  });

  if (!res.ok) {
    const msg = await readErrorBody(res);
    const err: ApiError = new Error(`HTTP ${res.status} ${res.statusText}${msg ? `: ${msg}` : ""}`);
    err.status = res.status;
    err.statusText = res.statusText;
    err.body = msg;
    throw err;
  }

  if (opts.expectEmpty) return undefined as unknown as T;

  // Some endpoints may legitimately return 204 without a body.
  if (res.status === 204) return undefined as unknown as T;

  return (await res.json()) as T;
}

export function apiPost<T>(path: string, body?: any, init?: RequestInit) {
  return apiJson<T>(path, { method: "POST", body, init });
}

export function apiPut<T>(path: string, body?: any, init?: RequestInit) {
  return apiJson<T>(path, { method: "PUT", body, init });
}

export function apiPatch<T>(path: string, body?: any, init?: RequestInit) {
  return apiJson<T>(path, { method: "PATCH", body, init });
}

export function apiDelete<T>(path: string, init?: RequestInit) {
  return apiJson<T>(path, { method: "DELETE", init });
}
