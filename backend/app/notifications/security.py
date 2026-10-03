"""Security events, read off the audit trail: app.audit.record() passes every event here
before committing it, so no route needs its own hook. Only metadata already in the audit
event is used (never request bodies or secrets)."""

import time

from sqlalchemy.orm import Session

from app.models import User
from app.notifications import ADMIN_CHANGE, LOGIN_ATTACK
from app.notifications.events import emit

# At most one login-attack alert per source address and channel in this window.
ATTACK_WINDOW_SECONDS = 15 * 60
ADMIN = "admin"  # app.permissions.Role.ADMIN (which imports app.audit, which imports this)


def _attack(db: Session, ip: str | None, data: dict) -> None:
    bucket = int(time.time()) // ATTACK_WINDOW_SECONDS
    emit(
        db,
        LOGIN_ATTACK,
        project_id=None,
        data={"ip": ip, **data},
        # Per kind too: password guessing and a wrong worker token are different problems.
        dedup_key=f"login_attack:{data['kind']}:{ip}:{bucket}",
    )


def _admin_change(db: Session, what: str, actor: str | None, target: str | None, ip: str | None):
    emit(
        db,
        ADMIN_CHANGE,
        project_id=None,
        data={"change": what, "by": actor, "user": target, "ip": ip},
    )


def from_audit(
    db: Session,
    action: str,
    *,
    outcome: str,
    actor: User | None,
    actor_username: str | None,
    target_name: str | None,
    ip: str | None,
    detail: dict | None,
) -> None:
    detail = detail or {}
    who = actor.username if actor else actor_username
    if outcome == "failure" and detail.get("locked_out"):
        # The attempt that locked a user name or address out says so (login, a second factor,
        # or re-entering the password for an account change); later ones are refused before
        # they are audited.
        kind = "second_factor" if detail.get("reason") == "bad second factor" else "password"
        _attack(db, ip, {"kind": kind, "user": who})
    elif action == "worker.auth_failed":
        _attack(db, ip, {"kind": "worker_token"})
    elif outcome != "success":
        return
    elif action == "user.create" and detail.get("role") == ADMIN:
        _admin_change(db, "created as a global admin", who, target_name, ip)
    elif (
        action == "user.update"
        and "role" in (detail.get("changed") or [])
        and detail.get("role") == ADMIN
    ):
        _admin_change(db, "made a global admin", who, target_name, ip)
    elif action == "user.totp_reset":
        _admin_change(db, "had two-factor login reset", who, target_name, ip)
    elif action == "auth.totp_disable":
        _admin_change(db, "turned off two-factor login", who, who, ip)
    elif (
        action == "auth.login"
        and detail.get("method")  # SSO (oidc, github); password logins carry no method
        and actor is not None
        and actor.role == ADMIN
    ):
        _admin_change(db, f"signed in as a global admin with {detail['method']}", who, who, ip)
