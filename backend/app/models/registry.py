"""Centralized model imports for metadata/alembic bootstrap."""


def load_all_models() -> None:
    # Keep explicit imports to avoid silent missing tables in metadata.
    from app.models import admin as _admin  # noqa: F401
    from app.models import agents as _agents  # noqa: F401
    from app.models import alert_rule_overrides as _alert_rule_overrides  # noqa: F401
    from app.models import alerts as _alerts  # noqa: F401
    from app.models import attack_chain as _attack_chain  # noqa: F401
    from app.models import correlation_rules as _correlation_rules  # noqa: F401
    from app.models import events as _events  # noqa: F401
    from app.models import inventory as _inventory  # noqa: F401
    from app.models import ip_enrichment_cache as _ip_enrichment_cache  # noqa: F401
    from app.models import portal_login_events as _portal_login_events  # noqa: F401
    from app.models import portal_otp_tokens as _portal_otp_tokens  # noqa: F401
    from app.models import portal_refresh_sessions as _portal_refresh_sessions  # noqa: F401
    from app.models import portal_users as _portal_users  # noqa: F401
    from app.models import search_index_offsets as _search_index_offsets  # noqa: F401
    from app.models import vuln as _vuln  # noqa: F401
