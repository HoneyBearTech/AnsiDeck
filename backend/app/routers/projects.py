from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.hardening import client_ip
from app.models import (
    Credential,
    Inventory,
    Playbook,
    Project,
    ProjectMember,
    Run,
    User,
    VaultPassword,
)
from app.permissions import (
    Permission,
    Scope,
    guard,
    is_global_admin,
    user_project_roles,
)
from app.schemas.projects import (
    MemberOut,
    MemberUpsert,
    ProjectCreate,
    ProjectListItem,
    ProjectOut,
    ProjectUpdate,
)
from app.scoping import require_project_permission
from app.storage import run_log_path

# GET (list): any member. Mutating project routes: global `projects:manage`.
_project_guard = guard(Permission.CONTENT_READ, Permission.PROJECTS_MANAGE, scope=Scope.PROJECT)
# Member management: `members:manage` inside the addressed project.
_member_guard = guard(Permission.MEMBERS_MANAGE, Permission.MEMBERS_MANAGE, scope=Scope.PROJECT)

router = APIRouter()


def _load_project(db: Session, project_id: int) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    return project


@router.get("", response_model=list[ProjectListItem])
def list_projects(
    user: User = Depends(_project_guard), db: Session = Depends(get_db)
) -> list[ProjectListItem]:
    query = db.query(Project)
    roles = user_project_roles(db, user)
    if not is_global_admin(user):
        query = query.filter(Project.id.in_(roles.keys())) if roles else query.filter(False)
    return [
        ProjectListItem(
            id=p.id,
            name=p.name,
            description=p.description,
            created_at=p.created_at,
            my_role="admin" if is_global_admin(user) else roles.get(p.id),
        )
        for p in query.order_by(Project.name).all()
    ]


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(
    payload: ProjectCreate,
    request: Request,
    actor: User = Depends(_project_guard),
    db: Session = Depends(get_db),
) -> Project:
    project = Project(name=payload.name.strip(), description=payload.description)
    db.add(project)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Project name already exists") from exc
    db.refresh(project)
    audit.record(
        db,
        "project.create",
        actor=actor,
        target_type="project",
        target_id=project.id,
        target_name=project.name,
        ip=client_ip(request),
        project_id=project.id,
    )
    return project


@router.patch("/{project_id}", response_model=ProjectOut)
def update_project(
    project_id: int,
    payload: ProjectUpdate,
    request: Request,
    actor: User = Depends(_project_guard),
    db: Session = Depends(get_db),
) -> Project:
    project = _load_project(db, project_id)
    changed = []
    if payload.name is not None and payload.name.strip() != project.name:
        project.name = payload.name.strip()
        changed.append("name")
    if payload.description is not None and payload.description != project.description:
        project.description = payload.description
        changed.append("description")
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Project name already exists") from exc
    db.refresh(project)
    audit.record(
        db,
        "project.update",
        actor=actor,
        target_type="project",
        target_id=project.id,
        target_name=project.name,
        ip=client_ip(request),
        project_id=project.id,
        detail={"changed": changed},
    )
    return project


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: int,
    request: Request,
    actor: User = Depends(_project_guard),
    db: Session = Depends(get_db),
) -> None:
    project = _load_project(db, project_id)
    counts = {
        "playbooks": db.query(Playbook).filter(Playbook.project_id == project_id).count(),
        "inventories": db.query(Inventory).filter(Inventory.project_id == project_id).count(),
        "credentials": db.query(Credential).filter(Credential.project_id == project_id).count(),
        "vault passwords": db.query(VaultPassword)
        .filter(VaultPassword.project_id == project_id)
        .count(),
    }
    remaining = {name: n for name, n in counts.items() if n}
    if remaining:
        listing = ", ".join(f"{n} {name}" for name, n in remaining.items())
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Project still has {listing}. Delete or move them first.",
        )

    name = project.name
    # An empty project's run history goes with it (runs are project-owned).
    for run in db.query(Run).filter(Run.project_id == project_id).all():
        run_log_path(run.id).unlink(missing_ok=True)
        db.delete(run)
    db.flush()
    db.delete(project)  # memberships cascade at the DB level
    db.commit()
    audit.record(
        db,
        "project.delete",
        actor=actor,
        target_type="project",
        target_id=project_id,
        target_name=name,
        ip=client_ip(request),
        project_id=project_id,
    )


def _member_out(user: User, role: str) -> MemberOut:
    return MemberOut(user_id=user.id, username=user.username, is_active=user.is_active, role=role)


def _guard_own_membership(actor: User, target_user_id: int) -> None:
    if actor.id == target_user_id and not is_global_admin(actor):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot change your own membership")


@router.get("/{project_id}/members", response_model=list[MemberOut])
def list_members(
    project_id: int,
    request: Request,
    actor: User = Depends(_member_guard),
    db: Session = Depends(get_db),
) -> list[MemberOut]:
    require_project_permission(db, actor, request, project_id, Permission.MEMBERS_MANAGE)
    rows = (
        db.query(ProjectMember, User)
        .join(User, User.id == ProjectMember.user_id)
        .filter(ProjectMember.project_id == project_id)
        .order_by(User.username)
        .all()
    )
    return [_member_out(user, member.role) for member, user in rows]


@router.put("/{project_id}/members/{user_id}", response_model=MemberOut)
def set_member(
    project_id: int,
    user_id: int,
    payload: MemberUpsert,
    request: Request,
    actor: User = Depends(_member_guard),
    db: Session = Depends(get_db),
) -> MemberOut:
    project = require_project_permission(db, actor, request, project_id, Permission.MEMBERS_MANAGE)
    _guard_own_membership(actor, user_id)
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    member = db.get(ProjectMember, (project_id, user_id))
    if member is None:
        db.add(ProjectMember(project_id=project_id, user_id=user_id, role=payload.role.value))
        action = "project.member_add"
    elif member.role != payload.role.value:
        member.role = payload.role.value
        action = "project.member_role_change"
    else:
        return _member_out(target, member.role)
    db.commit()
    audit.record(
        db,
        action,
        actor=actor,
        target_type="user",
        target_id=target.id,
        target_name=target.username,
        ip=client_ip(request),
        project_id=project.id,
        detail={"role": payload.role.value},
    )
    return _member_out(target, payload.role.value)


@router.delete("/{project_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(
    project_id: int,
    user_id: int,
    request: Request,
    actor: User = Depends(_member_guard),
    db: Session = Depends(get_db),
) -> None:
    project = require_project_permission(db, actor, request, project_id, Permission.MEMBERS_MANAGE)
    _guard_own_membership(actor, user_id)
    member = db.get(ProjectMember, (project_id, user_id))
    if member is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Membership not found")
    target = db.get(User, user_id)
    db.delete(member)
    db.commit()
    audit.record(
        db,
        "project.member_remove",
        actor=actor,
        target_type="user",
        target_id=user_id,
        target_name=target.username if target else None,
        ip=client_ip(request),
        project_id=project.id,
    )
