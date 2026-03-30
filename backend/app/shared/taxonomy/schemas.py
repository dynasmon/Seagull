from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class MitreTechniqueStat(BaseModel):
    technique_id: str = Field(..., min_length=1, max_length=32)
    technique: Optional[str] = Field(None, max_length=256)
    count: int = 0
    max_confidence: int = 0
    avg_confidence: float = 0.0


class MitreTacticCoverage(BaseModel):
    tactic: str = Field(..., min_length=1, max_length=64)
    total: int = 0
    max_confidence: int = 0
    avg_confidence: float = 0.0
    techniques: List[MitreTechniqueStat] = Field(default_factory=list)


class MitreCoverageResponse(BaseModel):
    window_minutes: int
    total_alerts: int
    tactics: List[MitreTacticCoverage] = Field(default_factory=list)


class MitreCaseSummary(BaseModel):
    progression: List[str] = Field(default_factory=list)
    tactics: List[MitreTacticCoverage] = Field(default_factory=list)
