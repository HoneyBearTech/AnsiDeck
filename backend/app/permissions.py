"""Role-based access control with per-project roles.

A user's *global* role is only meaningful for `admin` (superuser: every
permission in every project). Everyone else acts through project memberships
(`project_members`), each carrying an admin/operator/viewer role for that one
project. Every route carries a `guard(...)` dependency (a test enforces it); the
guard is a coarse "holds this permission somewhere" check, and handlers then
resolve the actual project through `app.scoping` so a resource can never be
reached from a project the caller doesn't belong to.
"""

from collections.abc import Callable
from enum import StrEnum

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import audit
from app.api_keys import KEY_ROLE_PREFIX
from app.db import get_db
from app.dependencies import get_current_user
from app.hardening import client_ip
from app.models import ProjectMember, User


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
    MEMBERS_MANAGE = "members:manage"  # add/remove/re-role members of one project
    API_KEYS_MANAGE = "api_keys:manage"  # create/revoke CI/CD keys of one project
    GALAXY_MANAGE = "galaxy:manage"  # installs run third-party code in the container
    USERS_MANAGE = "users:manage"
    PROJECTS_MANAGE = "projects:manage"  # create / rename / delete projects
    AUDIT_READ = "audit:read"


# Permissions that exist only at the global level; a project admin never gets them.
GLOBAL_ONLY = frozenset(
    {
        Permission.USERS_MANAGE,
        Permission.AUDIT_READ,
        Permission.GALAXY_MANAGE,
        Permission.PROJECTS_MANAGE,
    }
)

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

# What an API key may do in its one project, keyed by "key:<preset>" (the value its
# principal carries in place of a member role; the Role enum is untouched, so member
# APIs can never assign one). Deliberately no become, no extra_vars visibility, no writes.
KEY_ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    f"{KEY_ROLE_PREFIX}trigger": {
        Permission.CONTENT_READ,
        Permission.SECRETS_LIST,  # a run references a credential by id
        Permission.RUNS_TRIGGER,
    },
    f"{KEY_ROLE_PREFIX}read-only": {Permission.CONTENT_READ},
}

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class Scope(StrEnum):
    # Handlers resolve the project themselves via app.scoping helpers.
    PROJECT = "project"
    # Global-only operation; no per-project resolution involved.
    GLOBAL = "global"


def is_global_admin(user: User) -> bool:
    return user.role == Role.ADMIN.value


def project_role_permissions(role: str) -> set[Permission]:
    if role in KEY_ROLE_PERMISSIONS:
        return KEY_ROLE_PERMISSIONS[role]
    try:
        return ROLE_PERMISSIONS[Role(role)] - GLOBAL_ONLY
    except ValueError:
        return set()  # unknown role stored in the DB: fail closed


def user_project_roles(db: Session, user: User) -> dict[int, str]:
    cached = getattr(user, "_project_roles", None)
    if cached is None:
        rows = db.query(ProjectMember).filter(ProjectMember.user_id == user.id).all()
        cached = {row.project_id: row.role for row in rows}
        user._project_roles = cached  # type: ignore[attr-defined]  # per-request cache
    return cached


def project_permissions(db: Session, user: User, project_id: int) -> set[Permission]:
    """Everything `user` may do inside `project_id` (empty = not a member)."""
    if is_global_admin(user):
        return set(Permission)
    role = user_project_roles(db, user).get(project_id)
    return project_role_permissions(role) if role else set()


def holds_somewhere(db: Session, user: User, permission: Permission) -> bool:
    if is_global_admin(user):
        return True
    return any(
        permission in project_role_permissions(role)
        for role in user_project_roles(db, user).values()
    )


def effective_permissions(db: Session, user: User) -> set[Permission]:
    """Union across the user's projects (all of them for a global admin)."""
    if is_global_admin(user):
        return set(Permission)
    union: set[Permission] = set()
    for role in user_project_roles(db, user).values():
        union |= project_role_permissions(role)
    return union


def guard(
    read: Permission | None, write: Permission | None, *, scope: Scope, api_key: bool = False
) -> Callable[..., User]:
    """Route dependency: authenticates, then requires `read` for safe methods and
    `write` otherwise (None = any authenticated user) *in at least one project*.
    Handlers of Scope.PROJECT routes must then resolve the concrete project via
    app.scoping. Denials are audited. API keys are refused unless the route opts in
    with api_key=True (deny by default; a test pins the opted-in set)."""

    def dependency(
        request: Request,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        if getattr(user, "_api_key_id", None) is not None and not api_key:
            audit.record(
                db,
                "permission.denied",
                outcome="denied",
                actor=user,
                target_type="endpoint",
                target_name=f"{request.method} {request.url.path}",
                ip=client_ip(request),
                detail={"reason": "api keys cannot use this endpoint"},
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, "API keys cannot use this endpoint")
        required = read if request.method in SAFE_METHODS else write
        if required is not None and not holds_somewhere(db, user, required):
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
    dependency._scope = scope  # type: ignore[attr-defined]
    dependency._allows_api_key = api_key  # type: ignore[attr-defined]
    return dependency


def require_permission(permission: Permission, *, scope: Scope) -> Callable[..., User]:
    return guard(permission, permission, scope=scope)


def require_authenticated() -> Callable[..., User]:
    return guard(None, None, scope=Scope.GLOBAL)
