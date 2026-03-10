import type { HttpError } from "@/shared/lib/http";

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

function safeString(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const t = v.trim();
  return t ? t : null;
}

function readRequestId(err: unknown): string | null {
  if (!isObj(err)) return null;
  const httpErr = err as Partial<HttpError>;
  const body = httpErr.body;
  if (!isObj(body)) return null;
  return safeString(body.request_id);
}

function readDetail(err: unknown): string | null {
  if (!isObj(err)) return null;
  const httpErr = err as Partial<HttpError>;
  const body = httpErr.body;
  if (!isObj(body)) return null;
  const detail = body.detail;
  if (typeof detail === "string") return safeString(detail);
  if (Array.isArray(detail)) {
    const parts = detail
      .map((item) => {
        if (typeof item === "string") return safeString(item);
        if (isObj(item)) return safeString(item.msg);
        return null;
      })
      .filter(Boolean) as string[];
    return parts.length ? parts.join("; ") : null;
  }
  return null;
}

export function getErrorMessage(err: unknown, fallback: string): string {
  const explicit = isObj(err) ? safeString((err as { message?: unknown }).message) : null;
  const detail = readDetail(err);
  const base = explicit || detail || fallback;
  const requestId = readRequestId(err);
  return requestId ? `${base} (request_id: ${requestId})` : base;
}

