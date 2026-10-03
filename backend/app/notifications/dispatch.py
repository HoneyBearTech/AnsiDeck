"""Sends the outbox (notification_deliveries) from the API process: claims due rows with
SKIP LOCKED under a short lease, sends each, and records the outcome. Delivery is at least
once: a crash mid-send leaves the lease to run out, and the row is sent again."""

import asyncio
import logging

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import get_sessionmaker
from app.models import NotificationChannel, NotificationDelivery
from app.notifications import RUN_FAILED
from app.notifications.channels import Outcome, send
from app.notifications.events import DELIVERY_TOPIC, failed_tasks
from app.notify import notifier

logger = logging.getLogger(__name__)

# Waits after attempts 1-5 (attempt 6 is the last): about 1 h 40 min of retrying in all.
BACKOFF_SECONDS = (30, 120, 600, 1800, 3600)
MAX_ATTEMPTS = len(BACKOFF_SECONDS) + 1
LEASE_SECONDS = 60
BATCH = 20
IDLE_SECONDS = 5.0
# Per channel (Discord allows 30 a minute per webhook, Slack about 1 a second).
PER_MINUTE = 20
MIN_GAP_SECONDS = 1
MAX_RETRY_AFTER_SECONDS = 3600
RETENTION_DAYS = 30
_ACTIVE = ("pending", "sending")


def _in(seconds: float):
    return func.now() + func.make_interval(0, 0, 0, 0, 0, 0, seconds)


def _ago(seconds: float):
    return func.now() - func.make_interval(0, 0, 0, 0, 0, 0, seconds)


def claim(db: Session, limit: int = BATCH) -> list[int]:
    rows = db.scalars(
        select(NotificationDelivery)
        .where(
            NotificationDelivery.status.in_(_ACTIVE),
            NotificationDelivery.next_attempt_at <= func.now(),
        )
        .order_by(NotificationDelivery.next_attempt_at, NotificationDelivery.id)
        .limit(limit)
        .with_for_update(skip_locked=True)
    ).all()
    for row in rows:
        row.status = "sending"
        row.next_attempt_at = _in(LEASE_SECONDS)
    db.commit()
    return [row.id for row in rows]


def _wait_for_pacing(db: Session, channel_id: int) -> float | None:
    """Seconds this channel must wait before its next send, or None."""
    sent = NotificationDelivery.sent_at
    mine = NotificationDelivery.channel_id == channel_id
    if db.scalar(select(func.count()).where(mine, sent > _ago(60))) >= PER_MINUTE:
        return 60.0
    if db.scalar(select(func.count()).where(mine, sent > _ago(MIN_GAP_SECONDS))):
        return float(MIN_GAP_SECONDS)
    return None


def _record(delivery: NotificationDelivery, outcome: Outcome) -> None:
    delivery.last_status_code = outcome.status_code
    delivery.last_error = outcome.error[:300] if outcome.error else None
    if outcome.ok:
        delivery.status = "sent"
        delivery.sent_at = func.now()
        return
    if outcome.permanent or delivery.attempts >= MAX_ATTEMPTS:
        delivery.status = "failed"
        return
    wait = BACKOFF_SECONDS[delivery.attempts - 1]
    if outcome.retry_after is not None:
        wait = min(max(outcome.retry_after, 1.0), MAX_RETRY_AFTER_SECONDS)
    delivery.status = "pending"
    delivery.next_attempt_at = _in(wait)


def deliver(
    delivery_id: int, settings: Settings, transport: httpx.BaseTransport | None = None
) -> None:
    db = get_sessionmaker()()
    try:
        delivery = db.get(NotificationDelivery, delivery_id, with_for_update=True)
        if delivery is None or delivery.status != "sending":
            return
        channel = db.get(NotificationChannel, delivery.channel_id)
        if channel is None or not channel.enabled:
            delivery.status = "failed"
            delivery.last_error = "the channel was turned off before it could be sent"
            db.commit()
            return
        if (wait := _wait_for_pacing(db, channel.id)) is not None:
            delivery.status = "pending"
            delivery.next_attempt_at = _in(wait)
            db.commit()
            return
        payload = dict(delivery.payload)
        if delivery.event == RUN_FAILED and "failed_tasks" not in payload:
            payload["failed_tasks"] = failed_tasks(payload.get("run_id", -1))
            delivery.payload = payload  # the same list on every retry
        delivery.attempts += 1
        db.commit()  # the attempt counts even if this process dies while sending
        outcome = send(channel, delivery.event, payload, settings, transport)
        _record(delivery, outcome)
        db.commit()
        if not outcome.ok:
            logger.warning(
                "notification %s to channel %s: %s (attempt %s, %s)",
                delivery.id,
                channel.id,
                outcome.error,
                delivery.attempts,
                delivery.status,
            )
    finally:
        db.close()


def dispatch_once(
    settings: Settings | None = None, transport: httpx.BaseTransport | None = None
) -> int:
    """One batch; returns how many deliveries it handled."""
    settings = settings or get_settings()
    db = get_sessionmaker()()
    try:
        ids = claim(db)
    finally:
        db.close()
    for delivery_id in ids:
        try:
            deliver(delivery_id, settings, transport)
        except Exception:  # noqa: BLE001 - the lease runs out and it is tried again
            logger.exception("notification %s could not be delivered", delivery_id)
    return len(ids)


async def dispatch_forever() -> None:
    with notifier.listen(DELIVERY_TOPIC) as listener:
        while True:
            try:
                handled = await asyncio.to_thread(dispatch_once)
            except Exception:  # noqa: BLE001 - the next pass tries again
                logger.exception("notification pass failed")
                handled = 0
            if handled < BATCH:
                await listener.wait(IDLE_SECONDS)


def prune(db: Session) -> int:
    """Forgets finished deliveries after RETENTION_DAYS (the caller commits)."""
    result = db.execute(
        delete(NotificationDelivery).where(
            NotificationDelivery.status.in_(("sent", "failed")),
            NotificationDelivery.created_at < _ago(RETENTION_DAYS * 86400),
        )
    )
    return result.rowcount or 0
