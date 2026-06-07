from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class ObservabilityStatusOut(BaseModel):
    enabled: bool
    available: bool


class QueryCatalogueItemOut(BaseModel):
    key: str
    title: str
    description: str
    unit: str
    kinds: list[str]
    requires_window: bool


class QueryCatalogueOut(BaseModel):
    queries: list[QueryCatalogueItemOut]


class QueryEnvelopeOut(BaseModel):
    available: bool
    error: Optional[str] = None
    result: Optional[dict] = None
