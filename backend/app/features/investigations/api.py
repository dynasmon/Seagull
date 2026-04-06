from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Body, Depends, Query, Request, status

from app.core.audit import write_audit_event
from app.core.db import SessionLocal
from app.core.portal_auth import PortalPrincipal, get_current_user
from app.features.investigations import service
from app.features.investigations.schemas import (
    InvestigationBookmarkCreateIn,
    InvestigationBookmarkCreateResult,
    InvestigationBookmarkOut,
    InvestigationActivityOut,
    InvestigationNoteCreateIn,
    InvestigationNoteOut,
    InvestigationNoteUpdateIn,
    InvestigationPinOptionsIn,
    InvestigationWorkspaceCreateIn,
    InvestigationWorkspaceOut,
    InvestigationWorkspaceUpdateIn,
)
from app.shared.schemas import CursorPage


router = APIRouter(
    prefix="/investigations",
    tags=["investigations"],
    dependencies=[Depends(get_current_user)],
)


@router.get("/workspaces", response_model=CursorPage[InvestigationWorkspaceOut])
def list_workspaces(
    page_size: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(None, description="Opaque cursor from a previous call"),
    status: Optional[str] = Query(None, min_length=1, max_length=16),
    severity: Optional[str] = Query(None, min_length=1, max_length=16),
    priority: Optional[str] = Query(None, min_length=1, max_length=8),
    assignee: Optional[str] = Query(None, min_length=1, max_length=128),
    linked_attack_chain_case_id: Optional[int] = Query(None, ge=1),
    agent_id: Optional[str] = Query(None, min_length=1, max_length=64),
    search: Optional[str] = Query(None, min_length=1, max_length=128),
):
    db = SessionLocal()
    try:
        return service.list_workspaces(
            db,
            page_size=page_size,
            cursor=cursor,
            status=status,
            severity=severity,
            priority=priority,
            assignee=assignee,
            linked_attack_chain_case_id=linked_attack_chain_case_id,
            agent_id=agent_id,
            search=search,
        )
    finally:
        db.close()


@router.post("/workspaces", response_model=InvestigationWorkspaceOut, status_code=status.HTTP_201_CREATED)
def create_workspace(payload: InvestigationWorkspaceCreateIn, request: Request, user: PortalPrincipal = Depends(get_current_user)):
    db = SessionLocal()
    try:
        return service.create_workspace(
            db,
            payload=payload,
            request=request,
            user=user,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()


@router.get("/workspaces/{workspace_id}", response_model=InvestigationWorkspaceOut)
def get_workspace(workspace_id: int):
    db = SessionLocal()
    try:
        return service.get_workspace(db, workspace_id=workspace_id)
    finally:
        db.close()


@router.put("/workspaces/{workspace_id}", response_model=InvestigationWorkspaceOut)
def update_workspace(
    workspace_id: int,
    payload: InvestigationWorkspaceUpdateIn,
    request: Request,
    user: PortalPrincipal = Depends(get_current_user),
):
    db = SessionLocal()
    try:
        return service.update_workspace(
            db,
            workspace_id=workspace_id,
            payload=payload,
            request=request,
            user=user,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()


@router.post("/workspaces/{workspace_id}/close", response_model=InvestigationWorkspaceOut)
def close_workspace(workspace_id: int, request: Request, user: PortalPrincipal = Depends(get_current_user)):
    db = SessionLocal()
    try:
        return service.close_workspace(
            db,
            workspace_id=workspace_id,
            request=request,
            user=user,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()


@router.post("/workspaces/{workspace_id}/reopen", response_model=InvestigationWorkspaceOut)
def reopen_workspace(workspace_id: int, request: Request, user: PortalPrincipal = Depends(get_current_user)):
    db = SessionLocal()
    try:
        return service.reopen_workspace(
            db,
            workspace_id=workspace_id,
            request=request,
            user=user,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()


@router.get("/workspaces/{workspace_id}/notes", response_model=list[InvestigationNoteOut])
def list_workspace_notes(workspace_id: int, limit: int = Query(200, ge=1, le=1000)):
    db = SessionLocal()
    try:
        return service.list_notes(db, workspace_id=workspace_id, limit=limit)
    finally:
        db.close()


@router.post("/workspaces/{workspace_id}/notes", response_model=InvestigationNoteOut, status_code=status.HTTP_201_CREATED)
def create_workspace_note(
    workspace_id: int,
    payload: InvestigationNoteCreateIn,
    request: Request,
    user: PortalPrincipal = Depends(get_current_user),
):
    db = SessionLocal()
    try:
        return service.create_note(
            db,
            workspace_id=workspace_id,
            payload=payload,
            request=request,
            user=user,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()


@router.put("/notes/{note_id}", response_model=InvestigationNoteOut)
def update_note(
    note_id: int,
    payload: InvestigationNoteUpdateIn,
    request: Request,
    user: PortalPrincipal = Depends(get_current_user),
):
    db = SessionLocal()
    try:
        return service.update_note(
            db,
            note_id=note_id,
            payload=payload,
            request=request,
            user=user,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()


@router.delete("/notes/{note_id}")
def delete_note(note_id: int):
    db = SessionLocal()
    try:
        return service.delete_note(db, note_id=note_id)
    finally:
        db.close()


@router.get("/workspaces/{workspace_id}/bookmarks", response_model=CursorPage[InvestigationBookmarkOut])
def list_workspace_bookmarks(
    workspace_id: int,
    evidence_type: Optional[str] = Query(None, min_length=1, max_length=32),
    page_size: int = Query(100, ge=1, le=200),
    cursor: Optional[str] = Query(None, description="Opaque cursor from a previous call"),
):
    db = SessionLocal()
    try:
        return service.list_bookmarks(
            db,
            workspace_id=workspace_id,
            evidence_type=evidence_type,
            page_size=page_size,
            cursor=cursor,
        )
    finally:
        db.close()


@router.get("/workspaces/{workspace_id}/activity", response_model=CursorPage[InvestigationActivityOut])
def list_workspace_activity(
    workspace_id: int,
    page_size: int = Query(100, ge=1, le=200),
    cursor: Optional[str] = Query(None, description="Opaque cursor from a previous call"),
):
    db = SessionLocal()
    try:
        return service.list_activity(
            db,
            workspace_id=workspace_id,
            page_size=page_size,
            cursor=cursor,
        )
    finally:
        db.close()


@router.post("/workspaces/{workspace_id}/bookmarks", response_model=InvestigationBookmarkCreateResult)
def create_workspace_bookmark(
    workspace_id: int,
    payload: InvestigationBookmarkCreateIn,
    request: Request,
    user: PortalPrincipal = Depends(get_current_user),
):
    db = SessionLocal()
    try:
        return service.create_bookmark(
            db,
            workspace_id=workspace_id,
            payload=payload,
            request=request,
            user=user,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()


@router.delete("/bookmarks/{bookmark_id}")
def delete_workspace_bookmark(bookmark_id: int, request: Request, user: PortalPrincipal = Depends(get_current_user)):
    db = SessionLocal()
    try:
        return service.delete_bookmark(
            db,
            bookmark_id=bookmark_id,
            request=request,
            user=user,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()


@router.post("/workspaces/{workspace_id}/pin-event/{event_id}", response_model=InvestigationBookmarkCreateResult)
def pin_event(
    workspace_id: int,
    event_id: int,
    request: Request,
    payload: InvestigationPinOptionsIn | None = Body(default=None),
    user: PortalPrincipal = Depends(get_current_user),
):
    db = SessionLocal()
    try:
        return service.pin_event(
            db,
            workspace_id=workspace_id,
            event_id=event_id,
            payload=payload or InvestigationPinOptionsIn(),
            request=request,
            user=user,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()


@router.post("/workspaces/{workspace_id}/pin-protocol-intel-event/{event_id}", response_model=InvestigationBookmarkCreateResult)
def pin_protocol_intel_event(
    workspace_id: int,
    event_id: int,
    request: Request,
    payload: InvestigationPinOptionsIn | None = Body(default=None),
    user: PortalPrincipal = Depends(get_current_user),
):
    db = SessionLocal()
    try:
        return service.pin_protocol_intel_event(
            db,
            workspace_id=workspace_id,
            event_id=event_id,
            payload=payload or InvestigationPinOptionsIn(),
            request=request,
            user=user,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()


@router.post("/workspaces/{workspace_id}/pin-inventory-snapshot/{snapshot_id}", response_model=InvestigationBookmarkCreateResult)
def pin_inventory_snapshot(
    workspace_id: int,
    snapshot_id: int,
    request: Request,
    payload: InvestigationPinOptionsIn | None = Body(default=None),
    user: PortalPrincipal = Depends(get_current_user),
):
    db = SessionLocal()
    try:
        return service.pin_inventory_snapshot(
            db,
            workspace_id=workspace_id,
            snapshot_id=snapshot_id,
            payload=payload or InvestigationPinOptionsIn(),
            request=request,
            user=user,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()


@router.post("/workspaces/{workspace_id}/pin-response-result/{result_id}", response_model=InvestigationBookmarkCreateResult)
def pin_response_result(
    workspace_id: int,
    result_id: int,
    request: Request,
    payload: InvestigationPinOptionsIn | None = Body(default=None),
    user: PortalPrincipal = Depends(get_current_user),
):
    db = SessionLocal()
    try:
        return service.pin_response_result(
            db,
            workspace_id=workspace_id,
            result_id=result_id,
            payload=payload or InvestigationPinOptionsIn(),
            request=request,
            user=user,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()


@router.post("/workspaces/{workspace_id}/pin-attack-chain-case/{case_id}", response_model=InvestigationBookmarkCreateResult)
def pin_attack_chain_case(
    workspace_id: int,
    case_id: int,
    request: Request,
    payload: InvestigationPinOptionsIn | None = Body(default=None),
    user: PortalPrincipal = Depends(get_current_user),
):
    db = SessionLocal()
    try:
        return service.pin_attack_chain_case(
            db,
            workspace_id=workspace_id,
            case_id=case_id,
            payload=payload or InvestigationPinOptionsIn(),
            request=request,
            user=user,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()


@router.post("/workspaces/{workspace_id}/pin-attack-chain-step/{step_id}", response_model=InvestigationBookmarkCreateResult)
def pin_attack_chain_step(
    workspace_id: int,
    step_id: int,
    request: Request,
    payload: InvestigationPinOptionsIn | None = Body(default=None),
    user: PortalPrincipal = Depends(get_current_user),
):
    db = SessionLocal()
    try:
        return service.pin_attack_chain_step(
            db,
            workspace_id=workspace_id,
            step_id=step_id,
            payload=payload or InvestigationPinOptionsIn(),
            request=request,
            user=user,
            audit_writer=write_audit_event,
        )
    finally:
        db.close()
