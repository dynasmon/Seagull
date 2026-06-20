
# ``app.core.db.model_registry`` loads app.features.exposure.models along with
# the other feature-owned models.
from app.core.db.model_registry import load_all_models

__all__ = ["load_all_models"]
