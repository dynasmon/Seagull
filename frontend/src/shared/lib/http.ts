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
