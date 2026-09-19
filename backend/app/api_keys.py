"""API keys for CI/CD: token format, hashing and authentication.

A token is `ansd_<8 hex prefix>_<secret>`. The prefix is public (shown in the UI and
audit log, used to find the row); the secret carries 256 bits of entropy, so a plain
SHA-256 is the right hash — a slow one would only add latency to every request.
A verified key becomes a transient `User` that is never added to a session: never a
global admin, with exactly one project role, so every existing permission helper sees
only that project and only the preset's permissions (see permissions.KEY_ROLE_PERMISSIONS).
"""

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.models import ApiKey, User

TOKEN_PREFIX = "ansd"
KEY_PRESETS = ("trigger", "read-only")
KEY_ROLE_PREFIX = "key:"
MAX_TOKEN_LENGTH = 200
_LAST_USED_GRANULARITY = timedelta(minutes=1)
_DUMMY_HASH = hashlib.sha256(b"ansideck-dummy-api-key").hexdigest()


def aware(moment: datetime | None) -> datetime | None:
    """SQLite hands datetimes back naive; everything here is stored as UTC."""
    if moment is not None and moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> tuple[str, str]:
    """(token, prefix). The token is only ever returned to the caller once."""
    prefix = secrets.token_hex(4)
    return f"{TOKEN_PREFIX}_{prefix}_{secrets.token_urlsafe(32)}", prefix


def parse_prefix(token: str) -> str | None:
    if len(token) > MAX_TOKEN_LENGTH:
        return None
    parts = token.split("_", 2)  # the secret itself may contain "_"
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX or not parts[2]:
        return None
    prefix = parts[1]
    if len(prefix) != 8 or any(c not in "0123456789abcdef" for c in prefix):
        return None
    return prefix


def key_status(key: ApiKey, now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    if key.revoked_at is not None:
        return "revoked"
    if aware(key.expires_at) <= now:
        return "expired"
    return "active"


def principal_for(key: ApiKey) -> User:
    # "apikey:" can't collide with a real username (usernames may not contain ":").
    principal = User(
        username=f"apikey:{key.name}",
        password_hash="!",  # never verifiable
        role="viewer",
        is_active=True,
        session_version=0,
    )
    principal._project_roles = {key.project_id: f"{KEY_ROLE_PREFIX}{key.preset}"}  # type: ignore[attr-defined]
    principal._api_key_id = key.id  # type: ignore[attr-defined]
    return principal


def authenticate_api_key(
    db: Session, token: str, ip: str | None = None
) -> tuple[User | None, str | None, str | None]:
    """Returns (principal, failure_reason, prefix). The reason is for the audit log
    only — callers must not reveal it to the client."""
    prefix = parse_prefix(token)
    if prefix is None:
        return None, "malformed", None
    key = db.query(ApiKey).filter(ApiKey.prefix == prefix).first()
    supplied = hash_token(token)
    if key is None:
        hmac.compare_digest(supplied, _DUMMY_HASH)  # similar work either way
        return None, "unknown key", prefix
    if not hmac.compare_digest(supplied, key.token_hash):
        return None, "bad secret", prefix
    now = datetime.now(UTC)
    state = key_status(key, now)
    if state != "active":
        return None, state, prefix

    principal = principal_for(key)
    last_used = aware(key.last_used_at)
    if last_used is None or now - last_used >= _LAST_USED_GRANULARITY:
        key.last_used_at = now
        key.last_used_ip = ip
        db.commit()
    return principal, None, prefix
