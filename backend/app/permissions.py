"""Role-based access control: a code-level role -> permission map and the guard
dependency every route must carry (a test enforces this)."""

from collections.abc import Callable
from enum import StrEnum

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.dependencies import get_current_user
from app.hardening import client_ip
from app.models import User


class Role(StrEnum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class Permission(StrEnum):
    CONTENT_READ = "content:read"  # playbooks, inventories, runs (+output), galaxy state
    CONTENT_WRITE = "content:write"  # edit playbooks / inventories
    SECRETS_LIST = "secrets:list"  # list credentials / vault passwords (metadata only)
    SECRETS_MANAGE = "secrets:manage"  # create / delete credentials and vault passwords
    RUNS_TRIGGER = "runs:trigger"
    RUNS_BECOME = "runs:become"  # run as root
    RUNS_READ_EXTRA_VARS = "runs:read_extra_vars"
    VAULT_ENCRYPT = "vault:encrypt"
    VAULT_DECRYPT = "vault:decrypt"  # returns plaintext
    GALAXY_MANAGE = "galaxy:manage"  # installs run third-party code in the container
    USERS_MANAGE = "users:manage"
    AUDIT_READ = "audit:read"


_VIEWER = {Permission.CONTENT_READ}
_OPERATOR = _VIEWER | {
    Permission.CONTENT_WRITE,
    Permission.SECRETS_LIST,
    Permission.RUNS_TRIGGER,
    Permission.RUNS_READ_EXTRA_VARS,
    Permission.VAULT_ENCRYPT,
}
ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.VIEWER: _VIEWER,
    Role.OPERATOR: _OPERATOR,
    Role.ADMIN: set(Permission),
}

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def permissions_for(user: User) -> set[Permission]:
    try:
        return ROLE_PERMISSIONS[Role(user.role)]
    except ValueError:
        return set()  # unknown role stored in the DB: fail closed


def has_permission(user: User, permission: Permission) -> bool:
    return permission in permissions_for(user)


def guard(read: Permission | None, write: Permission | None) -> Callable[..., User]:
    """Route dependency: authenticates, then requires `read` for safe methods and
    `write` otherwise (None = any authenticated user). Denials are audited."""

    def dependency(
        request: Request,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        required = read if request.method in SAFE_METHODS else write
        if required is not None and not has_permission(user, required):
            audit.record(
                db,
                "permission.denied",
                outcome="denied",
                actor=user,
                target_type="endpoint",
                target_name=f"{request.method} {request.url.path}",
                ip=client_ip(request),
                detail={"required": required.value},
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You do not have permission to do that")
        return user

    dependency._is_permission_guard = True  # type: ignore[attr-defined]
    return dependency


def require_permission(permission: Permission) -> Callable[..., User]:
    return guard(permission, permission)


def require_authenticated() -> Callable[..., User]:
    return guard(None, None)
