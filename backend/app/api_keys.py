"""API keys for CI/CD: token format, hashing and authentication.

A token is `ansd_<8 hex prefix>_<secret>`. The prefix is public (shown in the UI and
audit log, used to find the row); the secret carries 256 bits of entropy, so a plain
SHA-256 is the right hash — a slow one would only add latency to every request.
A verified key becomes a transient `User` that is never added to a session: never a
global admin, with exactly one project role, so every existing permission helper sees
only that project and only the preset's permissions (see permissions.KEY_ROLE_PERMISSIONS).

A key may also be limited to some source addresses (checked here, for every request) and to
some playbooks and inventories (checked where runs start, app.routers.runs.queue_run).
"""

import hashlib
import hmac
import ipaddress
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, delete, func, or_
from sqlalchemy.orm import Session

from app.models import ApiKey, User

TOKEN_PREFIX = "ansd"  # noqa: S105 - public key prefix
KEY_PRESETS = ("trigger", "read-only")
KEY_ROLE_PREFIX = "key:"
MAX_TOKEN_LENGTH = 200
_LAST_USED_GRANULARITY = timedelta(minutes=1)
_DUMMY_HASH = hashlib.sha256(b"ansideck-dummy-api-key").hexdigest()
MAX_NETWORKS = 20
MAX_ALLOWED_ITEMS = 100


def parse_networks(values: list[str]) -> list[str]:
    """Addresses or CIDRs as stored (normalised), or ValueError naming the bad one."""
    networks: list[str] = []
    for raw in values:
        try:
            network = ipaddress.ip_network(raw.strip(), strict=False)
        except ValueError:
            raise ValueError(f"{raw[:60]!r} is not an IP address or CIDR") from None
        if str(network) not in networks:
            networks.append(str(network))
    return networks


def address_allowed(key: ApiKey, ip: str | None) -> bool:
    if not key.allowed_networks:
        return True
    try:
        address = ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return any(address in ipaddress.ip_network(n) for n in key.allowed_networks)


def run_limit_problem(principal: User, playbook_id: int, inventory_id: int) -> str | None:
    """Why an API key may not start this run, or None (also for people)."""
    playbooks = getattr(principal, "_allowed_playbook_ids", None)
    inventories = getattr(principal, "_allowed_inventory_ids", None)
    if playbooks is not None and playbook_id not in playbooks:
        return "This API key may not run this playbook"
    if inventories is not None and inventory_id not in inventories:
        return "This API key may not run against this inventory"
    return None


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
    if key.expires_at <= now:
        return "expired"
    return "active"


def creator_problem(db: Session, key: ApiKey) -> str | None:
    """Why the key's creator no longer vouches for it, or None. Checked on every use, so a key
    is suspended while its creator is deactivated, demoted or out of the project (and works
    again if that changes), and for good once they are deleted."""
    from app.permissions import Permission, project_permissions  # imports this module

    creator = db.get(User, key.created_by_id) if key.created_by_id is not None else None
    if creator is None:
        return "creator deleted"
    if not creator.is_active:
        return "creator deactivated"
    if Permission.API_KEYS_MANAGE not in project_permissions(db, creator, key.project_id):
        return "creator can no longer manage this project's keys"
    return None


def principal_for(key: ApiKey) -> User:
    # "apikey:" can't collide with a real username (usernames may not contain ":").
    principal = User(
        username=f"apikey:{key.name}",
        password_hash="!",  # noqa: S106 - never verifiable
        role="viewer",
        is_active=True,
        session_version=0,
    )
    principal._project_roles = {key.project_id: f"{KEY_ROLE_PREFIX}{key.preset}"}  # type: ignore[attr-defined]
    principal._api_key_id = key.id  # type: ignore[attr-defined]
    principal._allowed_playbook_ids = key.allowed_playbook_ids  # type: ignore[attr-defined]
    principal._allowed_inventory_ids = key.allowed_inventory_ids  # type: ignore[attr-defined]
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
    if problem := creator_problem(db, key):
        return None, f"suspended: {problem}", prefix
    if not address_allowed(key, ip):
        return None, "address not allowed", prefix

    principal = principal_for(key)
    last_used = key.last_used_at
    if last_used is None or now - last_used >= _LAST_USED_GRANULARITY:
        key.last_used_at = now
        key.last_used_ip = ip
        db.commit()
    return principal, None, prefix


def lifetime_days(key: ApiKey) -> int:
    """The lifetime a key was created with, in whole days (for its rotation)."""
    seconds = (key.expires_at - key.created_at).total_seconds()
    return max(1, min(365, round(seconds / 86400)))


def prune_keys(db: Session, retention_days: int) -> int:
    """Deletes keys that were revoked, or expired, more than `retention_days` ago (0 keeps
    them). Runs they started keep their history (triggered_by), and the audit log keeps their
    creation, rotation and revocation. The caller commits."""
    if retention_days <= 0:
        return 0
    cutoff = func.now() - func.make_interval(0, 0, 0, retention_days)
    gone = db.execute(
        delete(ApiKey).where(
            or_(
                ApiKey.revoked_at < cutoff,
                and_(ApiKey.revoked_at.is_(None), ApiKey.expires_at < cutoff),
            )
        )
    )
    return gone.rowcount
