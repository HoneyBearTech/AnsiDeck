"""Notification channels: global ones (global admins; every event, run events from all
projects) under /api/notifications, a project's own (its admins; that project's run events)
under /api/projects/{project_id}/notifications. Cookie sessions only: no API keys.

Channel URLs and tokens are write-only. Responses show a masked target, audit events show
only the kind and events, and delivery errors never include the URL."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.config import get_settings
from app.db import get_db
from app.hardening import FailureThrottle, client_ip
from app.models import NotificationChannel, NotificationDelivery, User
from app.notifications import EVENTS, KINDS, PROJECT_EVENTS, render
from app.notifications.channels import (
    ConfigError,
    describe,
    seal,
    send,
    unseal,
    validate,
)
from app.notifications.render import TEST
from app.permissions import Permission, Scope, guard, require_permission
from app.schemas.notifications import (
    CatalogOut,
    ChannelCreate,
    ChannelOut,
    ChannelUpdate,
    DeliveryOut,
    TestResult,
)
from app.scoping import require_project_permission

router = APIRouter()
project_router = APIRouter()

_global = require_permission(Permission.NOTIFICATIONS_GLOBAL, scope=Scope.GLOBAL)
_project = guard(
    Permission.NOTIFICATIONS_MANAGE, Permission.NOTIFICATIONS_MANAGE, scope=Scope.PROJECT
)
# The catalog is for anyone who may manage channels somewhere (a project admin is enough).
_any_manager = guard(Permission.NOTIFICATIONS_MANAGE, None, scope=Scope.GLOBAL)

MAX_CHANNELS = 50
DELIVERY_LOG = 50
test_send_throttle = FailureThrottle(max_failures=5, window_seconds=60)
_SECRET_FIELDS = ("url", "secret", "token", "user_key", "recipients")


# ------------------------------------------------------------------ helpers


def _events(events: list[str], project_id: int | None) -> list[str]:
    unknown = [e for e in events if e not in EVENTS]
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"unknown event: {unknown[0]}")
    if project_id is not None and (other := [e for e in events if e not in PROJECT_EVENTS]):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"{other[0]} is available on global channels only",
        )
    return sorted(set(events))


def _config(kind: str, stored: dict, changes: dict) -> dict:
    merged = dict(stored)
    for field in _SECRET_FIELDS:
        if changes.get(field) is not None:
            merged[field] = changes[field]
    if changes.get("secret") == "":
        merged.pop("secret", None)
    try:
        return validate(kind, merged, get_settings())
    except ConfigError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


def _out(db: Session, channel: NotificationChannel) -> dict:
    try:
        shown = describe(channel.kind, unseal(channel))
    except Exception:  # noqa: BLE001 - e.g. CREDENTIAL_ENCRYPTION_KEY changed
        shown = {"target": "(unreadable: re-enter its settings)"}
    last = db.scalars(
        select(NotificationDelivery)
        .where(NotificationDelivery.channel_id == channel.id)
        .order_by(NotificationDelivery.id.desc())
        .limit(1)
    ).first()
    return {
        "id": channel.id,
        "project_id": channel.project_id,
        "name": channel.name,
        "kind": channel.kind,
        "recipients": None,
        "has_secret": False,
        **shown,
        "events": channel.events,
        "enabled": channel.enabled,
        "created_by": channel.created_by,
        "created_at": channel.created_at,
        "updated_at": channel.updated_at,
        "last_delivery": (
            {
                "status": last.status,
                "event": last.event,
                "created_at": last.created_at,
                "error": last.last_error,
            }
            if last
            else None
        ),
    }


def _load(db: Session, project_id: int | None, channel_id: int) -> NotificationChannel:
    channel = db.get(NotificationChannel, channel_id)
    if channel is None or channel.project_id != project_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Channel not found")
    return channel


def _audit(
    db: Session,
    action: str,
    user: User,
    request: Request,
    channel: NotificationChannel,
    outcome: str = "success",
) -> None:
    audit.record(
        db,
        action,
        outcome=outcome,
        actor=user,
        target_type="notification_channel",
        target_id=channel.id,
        target_name=channel.name,
        ip=client_ip(request),
        project_id=channel.project_id,
        detail={"kind": channel.kind, "events": channel.events, "enabled": channel.enabled},
    )


def _list(db: Session, project_id: int | None) -> list[dict]:
    where = (
        NotificationChannel.project_id.is_(None)
        if project_id is None
        else NotificationChannel.project_id == project_id
    )
    channels = db.scalars(
        select(NotificationChannel).where(where).order_by(NotificationChannel.name)
    )
    return [_out(db, c) for c in channels]


def _create(
    db: Session, user: User, request: Request, project_id: int | None, payload: ChannelCreate
) -> dict:
    where = (
        NotificationChannel.project_id.is_(None)
        if project_id is None
        else NotificationChannel.project_id == project_id
    )
    names = set(db.scalars(select(NotificationChannel.name).where(where)))
    if payload.name in names:
        raise HTTPException(status.HTTP_409_CONFLICT, "A channel with that name already exists")
    if len(names) >= MAX_CHANNELS:
        raise HTTPException(status.HTTP_409_CONFLICT, f"At most {MAX_CHANNELS} channels here")
    events = _events(payload.events, project_id)
    config = _config(payload.kind, {}, payload.model_dump())
    channel = NotificationChannel(
        project_id=project_id,
        name=payload.name,
        kind=payload.kind,
        config_encrypted=seal(config),
        events=events,
        enabled=payload.enabled,
        created_by=user.username,
    )
    db.add(channel)
    db.commit()
    db.refresh(channel)
    _audit(db, "notification_channel.create", user, request, channel)
    return _out(db, channel)


def _update(
    db: Session,
    user: User,
    request: Request,
    project_id: int | None,
    channel_id: int,
    payload: ChannelUpdate,
) -> dict:
    channel = _load(db, project_id, channel_id)
    changes = payload.model_dump()
    if payload.name is not None and payload.name.strip() != channel.name:
        name = payload.name.strip()
        taken = db.scalar(
            select(func.count()).where(
                NotificationChannel.project_id.is_not_distinct_from(project_id),
                NotificationChannel.name == name,
            )
        )
        if taken:
            raise HTTPException(status.HTTP_409_CONFLICT, "A channel with that name already exists")
        channel.name = name
    if payload.events is not None:
        channel.events = _events(payload.events, project_id)
    if payload.enabled is not None:
        channel.enabled = payload.enabled
    if any(changes.get(f) is not None for f in _SECRET_FIELDS):
        try:
            stored = unseal(channel)
        except Exception:  # noqa: BLE001 - unreadable: the new values must stand alone
            stored = {}
        channel.config_encrypted = seal(_config(channel.kind, stored, changes))
    db.commit()
    db.refresh(channel)
    _audit(db, "notification_channel.update", user, request, channel)
    return _out(db, channel)


def _delete(
    db: Session, user: User, request: Request, project_id: int | None, channel_id: int
) -> None:
    channel = _load(db, project_id, channel_id)
    _audit(db, "notification_channel.delete", user, request, channel)
    db.delete(channel)
    db.commit()


def _test(
    db: Session, user: User, request: Request, project_id: int | None, channel_id: int
) -> dict:
    channel = _load(db, project_id, channel_id)
    if test_send_throttle.blocked(user.id):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "Too many test messages; try again in a minute"
        )
    test_send_throttle.record_failure(user.id)
    payload = {"sent_by": user.username}
    outcome = send(channel, TEST, payload, get_settings())
    db.add(
        NotificationDelivery(
            channel_id=channel.id,
            event=TEST,
            payload=payload,
            status="sent" if outcome.ok else "failed",
            attempts=1,
            last_status_code=outcome.status_code,
            last_error=outcome.error[:300] if outcome.error else None,
            sent_at=func.now() if outcome.ok else None,
        )
    )
    db.commit()
    _audit(
        db,
        "notification_channel.test",
        user,
        request,
        channel,
        outcome="success" if outcome.ok else "failure",
    )
    return {"ok": outcome.ok, "status_code": outcome.status_code, "error": outcome.error}


def _deliveries(db: Session, project_id: int | None, channel_id: int) -> list[dict]:
    channel = _load(db, project_id, channel_id)
    rows = db.scalars(
        select(NotificationDelivery)
        .where(NotificationDelivery.channel_id == channel.id)
        .order_by(NotificationDelivery.id.desc())
        .limit(DELIVERY_LOG)
    )
    return [
        {
            "id": d.id,
            "event": d.event,
            "title": render.build(d.event, d.payload).title,
            "status": d.status,
            "attempts": d.attempts,
            "last_status_code": d.last_status_code,
            "last_error": d.last_error,
            "created_at": d.created_at,
            "next_attempt_at": d.next_attempt_at if d.status in ("pending", "sending") else None,
            "sent_at": d.sent_at,
        }
        for d in rows
    ]


# ------------------------------------------------------------------ catalog


@router.get("/catalog", response_model=CatalogOut)
def catalog(_user: User = Depends(_any_manager)) -> dict:
    return {
        "events": [
            {
                "name": name,
                "label": i.label,
                "description": i.description,
                "project": i.project,
                "group": i.group,
            }
            for name, i in EVENTS.items()
        ],
        "kinds": list(KINDS),
        "email_available": bool(get_settings().smtp_host),
    }


# ------------------------------------------------------------------ global channels


@router.get("/channels", response_model=list[ChannelOut])
def list_global(_user: User = Depends(_global), db: Session = Depends(get_db)) -> list[dict]:
    return _list(db, None)


@router.post("/channels", response_model=ChannelOut, status_code=status.HTTP_201_CREATED)
def create_global(
    payload: ChannelCreate,
    request: Request,
    user: User = Depends(_global),
    db: Session = Depends(get_db),
) -> dict:
    return _create(db, user, request, None, payload)


@router.get("/channels/{channel_id}", response_model=ChannelOut)
def get_global(
    channel_id: int, _user: User = Depends(_global), db: Session = Depends(get_db)
) -> dict:
    return _out(db, _load(db, None, channel_id))


@router.patch("/channels/{channel_id}", response_model=ChannelOut)
def update_global(
    channel_id: int,
    payload: ChannelUpdate,
    request: Request,
    user: User = Depends(_global),
    db: Session = Depends(get_db),
) -> dict:
    return _update(db, user, request, None, channel_id, payload)


@router.delete("/channels/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_global(
    channel_id: int,
    request: Request,
    user: User = Depends(_global),
    db: Session = Depends(get_db),
) -> None:
    _delete(db, user, request, None, channel_id)


@router.post("/channels/{channel_id}/test", response_model=TestResult)
def test_global(
    channel_id: int,
    request: Request,
    user: User = Depends(_global),
    db: Session = Depends(get_db),
) -> dict:
    return _test(db, user, request, None, channel_id)


@router.get("/channels/{channel_id}/deliveries", response_model=list[DeliveryOut])
def deliveries_global(
    channel_id: int, _user: User = Depends(_global), db: Session = Depends(get_db)
) -> list[dict]:
    return _deliveries(db, None, channel_id)


# ------------------------------------------------------------------ project channels


def _member(db: Session, user: User, request: Request, project_id: int) -> None:
    require_project_permission(db, user, request, project_id, Permission.NOTIFICATIONS_MANAGE)


@project_router.get("/channels", response_model=list[ChannelOut])
def list_project(
    project_id: int,
    request: Request,
    user: User = Depends(_project),
    db: Session = Depends(get_db),
) -> list[dict]:
    _member(db, user, request, project_id)
    return _list(db, project_id)


@project_router.post("/channels", response_model=ChannelOut, status_code=status.HTTP_201_CREATED)
def create_project(
    project_id: int,
    payload: ChannelCreate,
    request: Request,
    user: User = Depends(_project),
    db: Session = Depends(get_db),
) -> dict:
    _member(db, user, request, project_id)
    return _create(db, user, request, project_id, payload)


@project_router.get("/channels/{channel_id}", response_model=ChannelOut)
def get_project(
    project_id: int,
    channel_id: int,
    request: Request,
    user: User = Depends(_project),
    db: Session = Depends(get_db),
) -> dict:
    _member(db, user, request, project_id)
    return _out(db, _load(db, project_id, channel_id))


@project_router.patch("/channels/{channel_id}", response_model=ChannelOut)
def update_project(
    project_id: int,
    channel_id: int,
    payload: ChannelUpdate,
    request: Request,
    user: User = Depends(_project),
    db: Session = Depends(get_db),
) -> dict:
    _member(db, user, request, project_id)
    return _update(db, user, request, project_id, channel_id, payload)


@project_router.delete("/channels/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: int,
    channel_id: int,
    request: Request,
    user: User = Depends(_project),
    db: Session = Depends(get_db),
) -> None:
    _member(db, user, request, project_id)
    _delete(db, user, request, project_id, channel_id)


@project_router.post("/channels/{channel_id}/test", response_model=TestResult)
def test_project(
    project_id: int,
    channel_id: int,
    request: Request,
    user: User = Depends(_project),
    db: Session = Depends(get_db),
) -> dict:
    _member(db, user, request, project_id)
    return _test(db, user, request, project_id, channel_id)


@project_router.get("/channels/{channel_id}/deliveries", response_model=list[DeliveryOut])
def deliveries_project(
    project_id: int,
    channel_id: int,
    request: Request,
    user: User = Depends(_project),
    db: Session = Depends(get_db),
) -> list[dict]:
    _member(db, user, request, project_id)
    return _deliveries(db, project_id, channel_id)
