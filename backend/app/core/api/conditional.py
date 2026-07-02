from __future__ import annotations

from fastapi import Response
from starlette import status


def _opaque_tag(tag: str) -> str:
    value = tag.strip()
    return value[2:] if value.startswith("W/") else value


def matches_if_none_match(client_etag: str | None, current_etag: str) -> bool:
    if not client_etag or not current_etag:
        return False
    incoming = client_etag.strip()
    if incoming == "*":
        return True
    incoming_tags = {_opaque_tag(tag) for tag in incoming.split(",") if tag.strip()}
    return _opaque_tag(current_etag) in incoming_tags


def maybe_not_modified(
    response: Response,
    client_etag: str | None,
    current_etag: str,
    *,
    outcome: str | None = None,
) -> Response | None:
    if not current_etag:
        return None
    response.headers["ETag"] = current_etag
    if outcome:
        response.headers["X-Cache-Outcome"] = outcome
    if matches_if_none_match(client_etag, current_etag):
        headers = {"ETag": current_etag}
        if outcome:
            headers["X-Cache-Outcome"] = outcome
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)
    return None
