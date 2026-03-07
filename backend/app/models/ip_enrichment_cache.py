from sqlalchemy import Column, DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class IpEnrichmentCacheModel(Base):
    __tablename__ = "ip_enrichment_cache"

    ip = Column(String(45), primary_key=True)
    country = Column(String(8), nullable=True)
    region = Column(String(128), nullable=True)
    city = Column(String(128), nullable=True)
    loc = Column(String(32), nullable=True)
    org = Column(String(256), nullable=True)
    asn = Column(String(32), nullable=True)
    asn_org = Column(String(256), nullable=True)
    data = Column(JSONB, nullable=False, default=dict)
    fetched_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
