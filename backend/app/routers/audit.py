from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import AuditEvent
from app.permissions import Permission, require_permission
from app.schemas.audit import AuditEventOut, AuditPage

router = APIRouter(dependencies=[Depends(require_permission(Permission.AUDIT_READ))])


@router.get("", response_model=AuditPage)
def list_audit_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    action: str | None = Query(None, max_length=64),
    actor: str | None = Query(None, max_length=150),
    outcome: str | None = Query(None, max_length=20),
    since: datetime | None = None,
    until: datetime | None = None,
    db: Session = Depends(get_db),
) -> AuditPage:
    query = db.query(AuditEvent)
    if action:
        query = query.filter(AuditEvent.action.startswith(action))
    if actor:
        query = query.filter(AuditEvent.actor_username == actor)
    if outcome:
        query = query.filter(AuditEvent.outcome == outcome)
    if since:
        query = query.filter(AuditEvent.created_at >= since)
    if until:
        query = query.filter(AuditEvent.created_at <= until)
    total = query.count()
    items = query.order_by(AuditEvent.id.desc()).offset(offset).limit(limit).all()
    return AuditPage(items=[AuditEventOut.model_validate(i) for i in items], total=total)
