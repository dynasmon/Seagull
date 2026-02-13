from fastapi import HTTPException, Request, status

from app.core.config import settings


def require_admin(request: Request) -> None:
    """Simple admin guard.

    Admin operations are intentionally minimal and token-based for the XDR foundation.
    """

    expected = (settings.NETWATCH_ADMIN_TOKEN or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin token is not configured",
        )

    got = (request.headers.get("X-Admin-Token") or "").strip()
    if not got or got != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
