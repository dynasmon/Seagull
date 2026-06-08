"""Backward-compatible model registry import path.

The canonical implementation lives in ``app.core.db.model_registry``. This
shim keeps older imports and source-level compatibility checks working while
the database bootstrap remains centralized in the db package.
"""

# ``app.core.db.model_registry`` loads app.features.exposure.models along with
# the other feature-owned models.
from app.core.db.model_registry import load_all_models

__all__ = ["load_all_models"]
