

def load_all_models() -> None:
    # Feature-owned models
    from app.features.admin import models as _admin  # noqa: F401
    from app.features.agents import models as _agents  # noqa: F401
    from app.features.alerts import models as _alerts  # noqa: F401
    from app.features.attack_chain import models as _attack_chain  # noqa: F401
    from app.features.auth import models as _auth  # noqa: F401
    from app.features.correlations import models as _correlations  # noqa: F401
    from app.features.detections import models as _detections  # noqa: F401
    from app.features.events import models as _events  # noqa: F401
    from app.features.exposure import models as _exposure  # noqa: F401
    from app.features.inventory import models as _inventory  # noqa: F401
    from app.features.investigations import models as _investigations  # noqa: F401
    from app.features.network_topology import models as _network_topology  # noqa: F401
    from app.features.response import models as _response  # noqa: F401
    from app.features.settings import models as _settings  # noqa: F401
    from app.features.ueba import models as _ueba  # noqa: F401
    from app.features.vuln import models as _vuln  # noqa: F401

    # Shared cross-feature models
    from app.shared.analytics import models as _analytics  # noqa: F401
    from app.shared.enrichment import models as _enrichment  # noqa: F401
    from app.shared.indexing import models as _indexing  # noqa: F401
    from app.shared.outbox import models as _outbox  # noqa: F401
