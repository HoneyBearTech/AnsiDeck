"""Audit trail helpers. Never pass secrets, request bodies, plaintext or
extra_vars in any field — only ids, names and small metadata."""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditEvent, User

logger = logging.getLogger(__name__)

_MAX_TEXT = 200


def _clip(value: str | None, limit: int = _MAX_TEXT) -> str | None:
    if value is None:
        return None
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _clean_detail(detail: dict[str, Any] | None) -> dict[str, Any] | None:
    if not detail:
        return None
    return {
        str(k)[:50]: (_clip(v) if isinstance(v, str) else v)
        for k, v in detail.items()
        if isinstance(v, str | int | float | bool | type(None) | list)
    }


def record(
    db: Session,
    action: str,
    *,
    outcome: str = "success",
    actor: User | None = None,
    actor_username: str | None = None,
    target_type: str | None = None,
    target_id: int | None = None,
    target_name: str | None = None,
    ip: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    # An audit failure must never break the request it describes.
    try:
        db.add(
            AuditEvent(
                actor_user_id=actor.id if actor else None,
                actor_username=_clip(actor.username if actor else actor_username, 150),
                action=action,
                target_type=target_type,
                target_id=target_id,
                target_name=_clip(target_name, 255),
                outcome=outcome,
                ip=_clip(ip, 64),
                detail=_clean_detail(detail),
            )
        )
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
        logger.exception("failed to write audit event %s", action)


def prune(db: Session, retention_days: int) -> int:
    if retention_days <= 0:
        return 0
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    deleted = db.query(AuditEvent).filter(AuditEvent.created_at < cutoff).delete()
    db.commit()
    return deleted
