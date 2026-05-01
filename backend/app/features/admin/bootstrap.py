from __future__ import annotations


def bootstrap_admin_user() -> None:
    """Deprecated legacy bootstrap path.

    Human authentication now uses only portal_users + /auth endpoints.
    """

    raise RuntimeError("bootstrap_admin_user is deprecated; use bootstrap_portal_admin")
