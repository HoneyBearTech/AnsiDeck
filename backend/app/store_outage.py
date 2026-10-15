"""While the secret store is down, runs and inventory refreshes that need it wait in the queue
instead of failing (SECRETS_STORE_WAIT_MINUTES; 0: fail at once, as before).

The outage is one row (models.SecretStoreOutage), shared by every API process: each sighting
(a job that couldn't read the store, a probe) holds it for HOLD_SECONDS, and a read that works
(a probe, a job that read the store) deletes it. While it is held, the claim queries skip runs
and refreshes that need the store, unless their wait is over: max(queued, outage start) plus
the setting. Once the hold lapses they are claimed again, so AnsiDeck tries every HOLD_SECONDS;
a job that still can't read the store puts its run back in the queue (app.queue.requeue_run),
or fails it once its wait is over."""

from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Credential, InventorySource, Run, SecretStoreOutage, VaultPassword

HOLD_SECONDS = 30


def wait_minutes() -> int:
    return get_settings().secrets_store_wait_minutes


def claim_params() -> dict:
    minutes = wait_minutes()
    return {"store_wait": minutes > 0, "wait_minutes": minutes}


def seen(db: Session, kind: str) -> datetime:
    """Records a sighting (the caller commits): starts the outage, or holds it longer. Returns
    when it began."""
    stmt = insert(SecretStoreOutage).values(
        id=1,
        kind=kind[:30],
        hold_until=func.now() + func.make_interval(0, 0, 0, 0, 0, 0, HOLD_SECONDS),
    )
    return db.scalar(
        stmt.on_conflict_do_update(
            index_elements=[SecretStoreOutage.id],
            set_={"kind": stmt.excluded.kind, "hold_until": stmt.excluded.hold_until},
        ).returning(SecretStoreOutage.since)
    )


def cleared(db: Session) -> bool:
    """The store works again (the caller commits, then wakes the workers when this is True)."""
    return db.scalar(delete(SecretStoreOutage).returning(SecretStoreOutage.id)) is not None


def current(db: Session) -> SecretStoreOutage | None:
    """The outage while a sighting holds it."""
    return db.scalars(
        select(SecretStoreOutage).where(SecretStoreOutage.hold_until > func.now())
    ).first()


def deadline(queued_at: datetime, since: datetime) -> datetime:
    """When something queued at `queued_at` stops waiting for an outage that began at `since`."""
    return max(queued_at, since) + timedelta(minutes=wait_minutes())


def run_needs_store(db: Session, run: Run) -> bool:
    """Whether the run's job reads the secret store (for wait_reason; app.queue's claim query
    has the same rule in SQL)."""
    credential = db.get(Credential, run.credential_id) if run.credential_id else None
    if credential is not None and (credential.store_path or credential.kind == "ssh_cert"):
        return True
    if run.vault_password_id is not None:
        vault_password = db.get(VaultPassword, run.vault_password_id)
        if vault_password is not None and vault_password.store_path:
            return True
    return bool(
        run.env_credential_ids
        and db.scalar(
            select(func.count()).where(
                Credential.id.in_(run.env_credential_ids), Credential.store_path.is_not(None)
            )
        )
    )


def refresh_needs_store(db: Session, inventory_id: int) -> bool:
    return bool(
        db.scalar(
            select(func.count())
            .select_from(InventorySource)
            .join(Credential, Credential.id == InventorySource.credential_id)
            .where(
                InventorySource.inventory_id == inventory_id,
                InventorySource.enabled,
                Credential.store_path.is_not(None),
            )
        )
    )
