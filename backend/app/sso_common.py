"""Pieces shared by the OIDC and GitHub sign-in flows.

Both flows prove *who someone is* to a third party and end in the app's normal session
cookie; who they are *inside AnsiDeck* (role, projects) is decided here, by mapping the
provider identity onto a pre-provisioned user. Nothing is ever created.

A provider may also manage project memberships from its groups (GitHub teams): those rows carry
`granted_by` = the provider, and only they are ever changed by a sign-in. Memberships an admin
set by hand are never touched.
"""

import base64
import hashlib
import hmac
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

import httpx
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.config import Settings
from app.models import Project, ProjectMember, User
from app.security import timed_serializer

STATE_MAX_AGE_SECONDS = 600
HTTP_TIMEOUT_SECONDS = 10.0


class SsoError(Exception):
    """`code` is what the browser is told ("failed" | "not_linked"); `reason` is for the
    audit log only."""

    def __init__(
        self, code: str, reason: str, *, user: User | None = None, email: str | None = None
    ) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason
        self.user = user
        self.email = email


def http_client() -> httpx.Client:
    return httpx.Client(timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=False)


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _state_serializer(flow: str) -> URLSafeTimedSerializer:
    # One salt per flow, so a state cookie from one provider can't be replayed at another.
    return timed_serializer(f"ansideck-{flow}-state")


def sign_state(flow: str, payload: dict) -> str:
    return _state_serializer(flow).dumps(payload)


def verify_state(flow: str, cookie: str, state: str) -> dict:
    """The signed payload of a fresh state cookie whose state matches the callback's."""
    try:
        data = _state_serializer(flow).loads(cookie, max_age=STATE_MAX_AGE_SECONDS)
        expected_state = data["s"]
    except (BadSignature, SignatureExpired, KeyError, TypeError) as exc:
        raise SsoError("failed", "state cookie missing, invalid or expired") from exc
    if not hmac.compare_digest(state.encode(), str(expected_state).encode()):
        raise SsoError("failed", "state mismatch")
    return data


def resolve_user(
    db: Session, settings: Settings, issuer: str, subject: str, emails: list[str]
) -> tuple[User, bool]:
    """(user, newly_linked). `emails` are addresses the provider has *verified*.

    Pre-provisioned only: match the bound (issuer, subject), else the one not-yet-linked
    user whose email is among `emails`. Never creates or re-links anyone, and a sign-in
    that could be either of two users is refused rather than guessed at."""
    # An address Unicode compatibility normalisation changes (a KELVIN SIGN for "K", say) is
    # never compared: str.lower() folds some of those into ASCII, so it would match another
    # person's address.
    emails = [e for e in emails if unicodedata.normalize("NFKC", e) == e]
    domains = {d.lower().lstrip("@") for d in settings.sso_allowed_email_domains}
    if domains:
        emails = [e for e in emails if e.rpartition("@")[2].lower() in domains]
    if not emails:
        raise SsoError("not_linked", "no verified email in an allowed domain")
    shown = emails[0]

    user = db.query(User).filter(User.sso_issuer == issuer, User.sso_subject == subject).first()
    newly_linked = False
    if user is None:
        candidates = (
            db.query(User)
            .filter(
                func.lower(User.email).in_([e.lower() for e in emails]),
                User.sso_subject.is_(None),
            )
            .all()
        )
        if not candidates:
            raise SsoError("not_linked", "no pre-provisioned account matches", email=shown)
        if len(candidates) > 1:
            raise SsoError("not_linked", "verified emails match more than one account", email=shown)
        user = candidates[0]
        newly_linked = True
    if not user.is_active:
        raise SsoError("not_linked", "account is deactivated", user=user, email=shown)
    if user.role == "admin" and not settings.sso_allow_admin:
        raise SsoError(
            "not_linked", "global admins cannot sign in with SSO", user=user, email=shown
        )
    if newly_linked:
        user.sso_issuer, user.sso_subject = issuer, subject
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise SsoError("failed", "identity is already linked to another user") from exc
    return user, newly_linked


# ------------------------------------------------------------------- managed memberships

ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}


@dataclass(frozen=True)
class Grant:
    role: str
    via: str  # the group (GitHub team) that grants it


@dataclass
class SsoSignIn:
    """What a provider's complete_login returns. `grants` None: the provider doesn't manage
    memberships; a dict (maybe empty): the user's `source` rows must match it."""

    user: User
    newly_linked: bool
    source: str | None = None
    grants: dict[int, Grant] | None = None
    notes: dict = field(default_factory=dict)


@dataclass(frozen=True)
class MembershipChange:
    action: str  # project.member_add | project.member_role_change | project.member_remove
    project_id: int
    role: str | None
    previous_role: str | None
    via: str | None


def desired_memberships(
    db: Session, role_map: Mapping[str, Mapping[str, str]], groups: Iterable[str]
) -> tuple[dict[int, Grant], list[str]]:
    """(project id -> the highest role any of `groups` maps it to, unknown project names).

    Groups and map keys are compared exactly (the caller normalises both). On a tie the
    alphabetically first group is named, so the audit trail doesn't flap between sign-ins."""
    wanted: dict[str, Grant] = {}
    for group in sorted(set(groups) & set(role_map)):
        for name, role in role_map[group].items():
            current = wanted.get(name)
            if current is None or ROLE_RANK[role] > ROLE_RANK[current.role]:
                wanted[name] = Grant(role, group)
    if not wanted:
        return {}, []
    ids = dict(db.query(Project.name, Project.id).filter(Project.name.in_(wanted)).all())
    unknown = sorted(name for name in wanted if name not in ids)
    return {ids[name]: grant for name, grant in wanted.items() if name in ids}, unknown


def sync_managed_memberships(
    db: Session, user: User, source: str, desired: Mapping[int, Grant]
) -> tuple[list[MembershipChange], list[int]]:
    """Make the user's `source` memberships equal `desired`, in one commit. Returns the
    changes and the projects left alone because a membership set by hand (or by another
    provider) is already there: those always win."""
    rows = {
        row.project_id: row
        for row in db.query(ProjectMember).filter(ProjectMember.user_id == user.id)
    }
    changes: list[MembershipChange] = []
    kept: list[int] = []
    for project_id, grant in sorted(desired.items()):
        row = rows.get(project_id)
        if row is None:
            db.add(
                ProjectMember(
                    project_id=project_id, user_id=user.id, role=grant.role, granted_by=source
                )
            )
            changes.append(
                MembershipChange("project.member_add", project_id, grant.role, None, grant.via)
            )
        elif row.granted_by != source:
            kept.append(project_id)
        elif row.role != grant.role:
            changes.append(
                MembershipChange(
                    "project.member_role_change", project_id, grant.role, row.role, grant.via
                )
            )
            row.role = grant.role
    for project_id, row in sorted(rows.items()):
        if row.granted_by == source and project_id not in desired:
            db.delete(row)
            changes.append(
                MembershipChange("project.member_remove", project_id, None, row.role, None)
            )
    _commit(db, changes)
    return changes, kept


def drop_managed_memberships(db: Session, user: User) -> list[MembershipChange]:
    """Remove every membership a provider granted the user (they come back at the next
    sign-in through it): for a sign-in that didn't go through the provider, and an unlink."""
    rows = (
        db.query(ProjectMember)
        .filter(ProjectMember.user_id == user.id, ProjectMember.granted_by.is_not(None))
        .order_by(ProjectMember.project_id)
        .all()
    )
    changes = []
    for row in rows:
        db.delete(row)
        changes.append(
            MembershipChange("project.member_remove", row.project_id, None, row.role, None)
        )
    _commit(db, changes)
    return changes


def _commit(db: Session, changes: list[MembershipChange]) -> None:
    if not changes:
        return
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise


def audit_membership_changes(
    db: Session,
    user: User,
    changes: Iterable[MembershipChange],
    *,
    via: str,
    ip: str | None,
    actor: User | None = None,
    actor_username: str | None = None,
) -> None:
    """One audit event per change. `via` names the cause; a change's own group, if any, is
    appended (e.g. "github team acme/ops")."""
    for change in changes:
        detail: dict[str, str] = {"via": f"{via} {change.via}" if change.via else via}
        if change.role:
            detail["role"] = change.role
        if change.previous_role:
            detail["previous_role"] = change.previous_role
        audit.record(
            db,
            change.action,
            actor=actor,
            actor_username=actor_username,
            target_type="user",
            target_id=user.id,
            target_name=user.username,
            ip=ip,
            project_id=change.project_id,
            detail=detail,
        )
