from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


SUPPORTED_ATTACK_STORY_SCHEMA_VERSIONS = {1}


class AttackStoryEntity(BaseModel):
    type: str = Field(..., min_length=1, max_length=64)
    field: str = Field(..., min_length=1, max_length=128)


class AttackStoryStageMatch(BaseModel):
    rule_ids: List[str] = Field(default_factory=list)
    correlation_rule_ids: List[int] = Field(default_factory=list)
    attack_step_kinds: List[str] = Field(default_factory=list)
    event_types: List[str] = Field(default_factory=list)

    @field_validator("rule_ids", "attack_step_kinds", "event_types", mode="before")
    @classmethod
    def _normalize_string_lists(cls, value: Any) -> List[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError("must be a list")
        out: List[str] = []
        seen: set[str] = set()
        for item in value:
            text = str(item or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            out.append(text)
        return out

    @field_validator("correlation_rule_ids", mode="before")
    @classmethod
    def _normalize_int_list(cls, value: Any) -> List[int]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError("must be a list")
        out: List[int] = []
        seen: set[int] = set()
        for item in value:
            try:
                num = int(item)
            except Exception as exc:
                raise ValueError(f"invalid correlation_rule_id: {item}") from exc
            if num in seen:
                continue
            seen.add(num)
            out.append(num)
        return out

    @model_validator(mode="after")
    def _validate_non_empty(self) -> "AttackStoryStageMatch":
        if not (self.rule_ids or self.correlation_rule_ids or self.attack_step_kinds or self.event_types):
            raise ValueError("at least one match selector is required")
        return self


class AttackStoryStage(BaseModel):
    id: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=96)
    tactic: str = Field(..., min_length=1, max_length=64)
    technique_id: Optional[str] = Field(default=None, max_length=32)
    required: bool = True
    min_signals: int = Field(default=1, ge=1, le=1000)
    after: Optional[str] = Field(default=None, max_length=64)
    within_seconds: Optional[int] = Field(default=None, ge=1, le=7 * 24 * 3600)
    match: AttackStoryStageMatch
    score_delta: int = Field(default=0, ge=0, le=1000)
    confidence_weight: float = Field(default=1.0, ge=0.0, le=2.0)


class AttackStoryScoring(BaseModel):
    story_match_bonus: int = Field(default=0, ge=0, le=1000)
    max_story_score: Optional[int] = Field(default=None, ge=0, le=5000)


class AttackStoryAttack(BaseModel):
    summary: Optional[str] = Field(default=None, max_length=512)
    techniques: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

    @field_validator("techniques", "tags", mode="before")
    @classmethod
    def _normalize_attack_lists(cls, value: Any) -> List[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError("must be a list")
        out: List[str] = []
        seen: set[str] = set()
        for item in value:
            text = str(item or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            out.append(text)
        return out


class AttackStoryResponse(BaseModel):
    summary: Optional[str] = Field(default=None, max_length=512)
    recommendations: List[str] = Field(default_factory=list)

    @field_validator("recommendations", mode="before")
    @classmethod
    def _normalize_recommendations(cls, value: Any) -> List[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError("must be a list")
        out: List[str] = []
        seen: set[str] = set()
        for item in value:
            text = str(item or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            out.append(text)
        return out


class AttackStoryTemplate(BaseModel):
    schema_version: int = Field(..., ge=1, le=16)
    id: str = Field(..., min_length=1, max_length=96)
    name: str = Field(..., min_length=1, max_length=128)
    description: str = Field(..., min_length=1, max_length=1024)
    enabled: bool = True
    maturity: str = Field(default="stable", min_length=1, max_length=32)
    entity: AttackStoryEntity
    maxspan_seconds: int = Field(..., ge=1, le=14 * 24 * 3600)
    stages: List[AttackStoryStage] = Field(default_factory=list)
    scoring: AttackStoryScoring = Field(default_factory=AttackStoryScoring)
    attack: AttackStoryAttack = Field(default_factory=AttackStoryAttack)
    response: AttackStoryResponse = Field(default_factory=AttackStoryResponse)
    source_file: Optional[str] = None

    @field_validator("schema_version")
    @classmethod
    def _validate_schema_version(cls, value: int) -> int:
        if int(value) not in SUPPORTED_ATTACK_STORY_SCHEMA_VERSIONS:
            raise ValueError(f"unsupported schema_version: {value}")
        return int(value)

    @model_validator(mode="after")
    def _validate_cross_references(self) -> "AttackStoryTemplate":
        if not self.stages:
            raise ValueError("at least one stage is required")

        stage_ids = [stage.id for stage in self.stages]
        if len(stage_ids) != len(set(stage_ids)):
            raise ValueError("duplicate stage id in story")

        stage_map = {stage.id: stage for stage in self.stages}
        for index, stage in enumerate(self.stages):
            if stage.after:
                if stage.after not in stage_map:
                    raise ValueError(f"stage {stage.id} references unknown after stage {stage.after}")
                if stage.after == stage.id:
                    raise ValueError(f"stage {stage.id} cannot reference itself")
                if stage_ids.index(stage.after) >= index:
                    raise ValueError(f"stage {stage.id} must reference an earlier stage")

        return self


class AttackStoryReport(BaseModel):
    stories: List[AttackStoryTemplate] = Field(default_factory=list)
    errors: List[Dict[str, Any]] = Field(default_factory=list)
