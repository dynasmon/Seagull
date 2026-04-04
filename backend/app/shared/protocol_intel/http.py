from __future__ import annotations

from typing import Any, Dict, Optional, Tuple


def _safe_ascii(b: bytes) -> str:
    try:
        return b.decode("iso-8859-1", "replace")
    except Exception:
        return ""


def _parse_request_line(line: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    parts = [p for p in line.strip().split(" ") if p]
    if len(parts) < 2:
        return None, None, None
    method = parts[0].upper()[:12]
    path = parts[1][:2048]
    version = parts[2].upper()[:16] if len(parts) >= 3 else None
    return method, path, version


def parse_http_message(payload: bytes) -> Dict[str, Any]:
    """Parse an HTTP/1.x request or response (best-effort).

    Returns keys prefixed by http_*.
    """

    out: Dict[str, Any] = {}

    # We only need headers; cap split.
    text = _safe_ascii(payload[:8192])
    if "\r\n" not in text:
        return out

    head, *_ = text.split("\r\n\r\n", 1)
    lines = head.split("\r\n")
    if not lines:
        return out

    first = lines[0].strip()
    method: Optional[str] = None
    path: Optional[str] = None
    version: Optional[str] = None

    if first.upper().startswith("HTTP/"):
        parts = [p for p in first.split(" ") if p]
        if len(parts) < 2:
            return out
        out["http_direction"] = "response"
        out["http_version"] = parts[0].upper()[:16]
        out["http_status"] = parts[1][:8]
    else:
        method, path, version = _parse_request_line(first)
        if not method:
            return out
        out["http_direction"] = "request"
        out["http_method"] = method
        out["http_path"] = path
        if version:
            out["http_version"] = version

    headers: Dict[str, str] = {}
    for ln in lines[1:]:
        if not ln or ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        k = k.strip().lower()[:64]
        v = v.strip()[:2048]
        if k and k not in headers:
            headers[k] = v

    host = headers.get("host")
    ua = headers.get("user-agent")
    ref = headers.get("referer")

    if host:
        out["http_host"] = host
    if ua:
        out["http_user_agent"] = ua
    if ref:
        out["http_referer"] = ref

    # Useful for hunting: "method host path" canonical form.
    if host and method and path:
        out["http_target"] = f"{method} {host}{path}"

    return out


# Backward-compatible alias.
parse_http_request = parse_http_message
