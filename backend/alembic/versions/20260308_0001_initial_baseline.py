
from __future__ import annotations

from alembic import op
from app.core.db import Base
from app.core.db.model_registry import load_all_models
from app.core.db.schema_bootstrap import bootstrap_schema

revision = "20260308_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    load_all_models()
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind, checkfirst=True)
    bootstrap_schema(bind)


def downgrade() -> None:
    load_all_models()
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind, checkfirst=True)
