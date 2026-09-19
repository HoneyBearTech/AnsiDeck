"""Per-project resolution helpers. Every handler that touches a project-owned
resource goes through these, so a resource can only be reached by members of its
project (404 otherwise — never a 403 that would confirm it exists)."""

from typing import Any

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from app import audit
from app.hardening import client_ip
from app.models import Project, User
from app.permissions import (
    Permission,
    is_global_admin,
    project_permissions,
    project_role_permissions,
    user_project_roles,
)


def deny(
    db: Session, user: User, request: Request | None, permission: Permission, project_id: int | None
) -> HTTPException:
    audit.record(
        db,
        "permission.denied",
        outcome="denied",
        actor=user,
        target_type="endpoint",
        target_name=f"{request.method} {request.url.path}" if request else None,
        ip=client_ip(request) if request else None,
        project_id=project_id,
        detail={"required": permission.value},
    )
    return HTTPException(status.HTTP_403_FORBIDDEN, "You do not have permission to do that")


def get_scoped(
    db: Session,
    user: User,
    request: Request | None,
    model: type[Any],
    obj_id: int,
    permission: Permission,
    not_found: str,
) -> Any:
    """Fetch a project-owned row. 404 when it doesn't exist *or* the caller isn't a
    member of its project; 403 only for a member lacking `permission`."""
    obj = db.get(model, obj_id)
    if obj is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, not_found)
    perms = project_permissions(db, user, obj.project_id)
    if not perms:
        raise HTTPException(status.HTTP_404_NOT_FOUND, not_found)
    if permission not in perms:
        raise deny(db, user, request, permission, obj.project_id)
    return obj


def require_project_permission(
    db: Session, user: User, request: Request | None, project_id: int, permission: Permission
) -> Project:
    project = db.get(Project, project_id)
    perms = project_permissions(db, user, project_id) if project else set()
    if project is None or not perms:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    if permission not in perms:
        raise deny(db, user, request, permission, project_id)
    return project


def readable_project_ids(
    db: Session,
    user: User,
    request: Request | None,
    permission: Permission,
    project_id: int | None,
) -> list[int] | None:
    """Projects a list endpoint may return rows from. None = unrestricted (global
    admin without a filter). With an explicit project_id the caller must hold
    `permission` there."""
    if project_id is not None:
        require_project_permission(db, user, request, project_id, permission)
        return [project_id]
    if is_global_admin(user):
        return None
    return [
        pid
        for pid, role in user_project_roles(db, user).items()
        if permission in project_role_permissions(role)
    ]


def resolve_write_project(
    db: Session,
    user: User,
    request: Request | None,
    project_id: int | None,
    permission: Permission,
) -> int:
    """The project a create endpoint writes into. An explicit id must be writable;
    when omitted, it is only accepted if exactly one project qualifies."""
    if project_id is not None:
        require_project_permission(db, user, request, project_id, permission)
        return project_id
    if is_global_admin(user):
        candidates = [pid for (pid,) in db.query(Project.id).all()]
    else:
        candidates = [
            pid
            for pid, role in user_project_roles(db, user).items()
            if permission in project_role_permissions(role)
        ]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No project available to create this in")
    raise HTTPException(
        status.HTTP_400_BAD_REQUEST, "project_id is required (you can write to several projects)"
    )
