from sqlalchemy import BigInteger, Column, DateTime, Text, func

from app.core.db import Base


class SearchIndexOffsetModel(Base):
    __tablename__ = "search_index_offsets"

    name = Column(Text, primary_key=True, nullable=False)
    last_id = Column(BigInteger, nullable=False, default=0)
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
