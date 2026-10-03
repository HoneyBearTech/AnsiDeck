"""Raised/cleared state of ops alerts (notification_alerts): raise_alert() is True only for
the first raise of an episode, clear_alert() only when something was raised, so an alert
fires once and its all-clear once, however often the condition is checked."""

from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models import NotificationAlert


def raise_alert(db: Session, key: str, data: dict | None = None) -> bool:
    raised = db.execute(
        insert(NotificationAlert)
        .values(key=key, data=data)
        .on_conflict_do_nothing(index_elements=["key"])
        .returning(NotificationAlert.key)
    ).first()
    return raised is not None


def clear_alert(db: Session, key: str) -> bool:
    cleared = db.execute(
        delete(NotificationAlert)
        .where(NotificationAlert.key == key)
        .returning(NotificationAlert.key)
    ).first()
    return cleared is not None


def clear_alerts(db: Session, keys: list[str]) -> None:
    """Forgets alerts without an all-clear (e.g. of workers pruned from the registry)."""
    if keys:
        db.execute(delete(NotificationAlert).where(NotificationAlert.key.in_(keys)))
