from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, model_validator, validator


WorkspaceStatus = Literal["open", "contained", "resolved", "closed"]
WorkspaceSeverity = Literal["low", "medium", "high", "critical"]
WorkspacePriority = Literal["p1", "p2", "p3", "p4"]
WorkspaceTriageState = Literal["untriaged", "triage", "assigned", "investigating", "contained", "closed"]

EvidenceType = Literal[
    "net_event",
    "protocol_intel",
    "inventory_snapshot",
    "response_action_result",
    "attack_chain_case",
    "attack_chain_step",
]


class InvestigationWorkspaceCreateIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=4000)

    status: WorkspaceStatus = "open"
    severity: WorkspaceSeverity = "medium"
    priority: WorkspacePriority = "p3"

    triage_state: WorkspaceTriageState = "untriaged"
    assignee: Optional[str] = Field(default=None, max_length=128)

    linked_attack_chain_case_id: Optional[int] = Field(default=None, ge=1)
    primary_agent_id: Optional[str] = Field(default=None, min_length=1, max_length=64)

    initial_note: Optional[str] = Field(default=None, max_length=4000)


class InvestigationWorkspaceUpdateIn(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=4000)

    status: Optional[WorkspaceStatus] = None
    severity: Optional[WorkspaceSeverity] = None
    priority: Optional[WorkspacePriority] = None

    triage_state: Optional[WorkspaceTriageState] = None
    assignee: Optional[str] = Field(default=None, max_length=128)

    linked_attack_chain_case_id: Optional[int] = Field(default=None, ge=1)
    primary_agent_id: Optional[str] = Field(default=None, min_length=1, max_length=64)


class InvestigationWorkspaceOut(BaseModel):
    id: int
    workspace_key: str

    title: str
    description: Optional[str] = None

    status: WorkspaceStatus
    severity: WorkspaceSeverity
    priority: WorkspacePriority

    triage_state: WorkspaceTriageState = "untriaged"
    assignee: Optional[str] = None

    created_by: str
    updated_by: str

    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None

    linked_attack_chain_case_id: Optional[int] = None
    primary_agent_id: Optional[str] = None

    summary: Dict[str, Any] = Field(default_factory=dict)

    notes_count: int = 0
    bookmarks_count: int = 0
    evidence_type_counts: Dict[str, int] = Field(default_factory=dict)

    class Config:
        from_attributes = True


class InvestigationNoteCreateIn(BaseModel):
    body: str = Field(..., min_length=1, max_length=4000)

    @validator("body", pre=True)
    def _normalize_body(cls, v: Any) -> str:
        s = str(v or "").strip()
        if not s:
            raise ValueError("body is required")
        return s


class InvestigationNoteUpdateIn(BaseModel):
    body: str = Field(..., min_length=1, max_length=4000)

    @validator("body", pre=True)
    def _normalize_body(cls, v: Any) -> str:
        s = str(v or "").strip()
        if not s:
            raise ValueError("body is required")
        return s


class InvestigationNoteOut(BaseModel):
    id: int
    workspace_id: int
    author: str
    body: str
    created_at: datetime
    updated_at: datetime
    edited: bool = False

    class Config:
        from_attributes = True


class InvestigationPinOptionsIn(BaseModel):
    source_module: Optional[str] = Field(default=None, min_length=1, max_length=64)
    evidence_subtype: Optional[str] = Field(default=None, min_length=1, max_length=64)
    note: Optional[str] = Field(default=None, max_length=1000)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @validator("tags", pre=True)
    def _normalize_tags(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if not isinstance(v, list):
            raise ValueError("tags must be an array")
        out: list[str] = []
        seen: set[str] = set()
        for item in v[:32]:
            s = str(item or "").strip()
            if not s:
                continue
            if len(s) > 48:
                s = s[:48]
            lk = s.lower()
            if lk in seen:
                continue
            seen.add(lk)
            out.append(s)
        return out

    @validator("source_module", "evidence_subtype", "note", pre=True)
    def _normalize_optional_text(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = str(v).strip()
        return s or None


class InvestigationBookmarkCreateIn(InvestigationPinOptionsIn):
    evidence_type: EvidenceType

    source_event_id: Optional[int] = Field(default=None, ge=1)
    inventory_snapshot_id: Optional[int] = Field(default=None, ge=1)
    response_action_result_id: Optional[int] = Field(default=None, ge=1)
    attack_chain_case_id: Optional[int] = Field(default=None, ge=1)
    attack_chain_step_id: Optional[int] = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _validate_source_keys(self):
        et = str(self.evidence_type or "").strip()
        source_keys = {
            "source_event_id": self.source_event_id,
            "inventory_snapshot_id": self.inventory_snapshot_id,
            "response_action_result_id": self.response_action_result_id,
            "attack_chain_case_id": self.attack_chain_case_id,
            "attack_chain_step_id": self.attack_chain_step_id,
        }
        non_null = [k for k, v in source_keys.items() if v is not None]

        expected = {
            "net_event": "source_event_id",
            "protocol_intel": "source_event_id",
            "inventory_snapshot": "inventory_snapshot_id",
            "response_action_result": "response_action_result_id",
            "attack_chain_case": "attack_chain_case_id",
            "attack_chain_step": "attack_chain_step_id",
        }.get(et)

        if not expected:
            raise ValueError("Unsupported evidence_type")
        if source_keys.get(expected) is None:
            raise ValueError(f"{expected} is required for evidence_type={et}")
        if any(k != expected for k in non_null):
            raise ValueError("Only one evidence source id is allowed and must match evidence_type")
        return self


class InvestigationBookmarkOut(BaseModel):
    id: int
    workspace_id: int

    evidence_type: EvidenceType
    evidence_subtype: Optional[str] = None
    source_module: str

    title: str
    summary: Optional[str] = None

    agent_id: Optional[str] = None
    observed_at: Optional[datetime] = None

    created_by: str
    created_at: datetime

    ref_id: Optional[str] = None
    ref_table: Optional[str] = None
    fingerprint: Optional[str] = None

    tags: List[str] = Field(default_factory=list)
    payload_snapshot: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class InvestigationBookmarkCreateResult(BaseModel):
    created: bool
    duplicate_of_id: Optional[int] = None
    bookmark: InvestigationBookmarkOut
