"""Pieces shared by the OIDC and GitHub sign-in flows.

Both flows prove *who someone is* to a third party and end in the app's normal session
cookie; who they are *inside AnsiDeck* (role, projects) is decided here, by mapping the
provider identity onto a pre-provisioned user. Nothing is ever created.
"""

import base64
import hashlib
import hmac

import httpx
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.models import User

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
    return URLSafeTimedSerializer(get_settings().auth_secret_key, salt=f"ansideck-{flow}-state")


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
