from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.core.portal_auth import PortalPrincipal, get_current_user, require_admin


class _FakeDB:
    def __init__(self, row):
        self._row = row

    def get(self, _model, _uid):
        return self._row

    def close(self):
        return None


def _req(headers: dict[str, str]) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/auth/me",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        }
    )


def test_require_admin_blocks_non_admin() -> None:
    with pytest.raises(HTTPException) as exc:
        require_admin(PortalPrincipal(id=1, username="u", role="user"))
    assert exc.value.status_code == 403


def test_get_current_user_from_valid_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    row = SimpleNamespace(id=7, username="evelyn", role="admin", is_active=True)
    monkeypatch.setattr("app.core.portal_auth.decode_token", lambda _t: {"typ": "access", "sub": "7"})
    monkeypatch.setattr("app.core.portal_auth.SessionLocal", lambda: _FakeDB(row))

    user = get_current_user(_req({"Authorization": "Bearer token-abc"}))
    assert user.id == 7
    assert user.username == "evelyn"
    assert user.is_admin is True


def test_get_current_user_missing_token() -> None:
    with pytest.raises(HTTPException) as exc:
        get_current_user(_req({}))
    assert exc.value.status_code == 401
