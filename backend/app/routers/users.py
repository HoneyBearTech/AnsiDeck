from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.crypto import hash_password
from app.db import get_db
from app.hardening import client_ip
from app.models import User
from app.permissions import Permission, Role, require_permission
from app.schemas.users import UserAdminOut, UserCreate, UserUpdate

_guard = require_permission(Permission.USERS_MANAGE)
router = APIRouter(dependencies=[Depends(_guard)])


def _active_admin_count(db: Session) -> int:
    return db.query(User).filter(User.role == Role.ADMIN.value, User.is_active.is_(True)).count()


def _load(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return user


def _is_last_active_admin(db: Session, user: User) -> bool:
    return user.role == Role.ADMIN.value and user.is_active and _active_admin_count(db) <= 1


@router.get("", response_model=list[UserAdminOut])
def list_users(db: Session = Depends(get_db)) -> list[User]:
    return db.query(User).order_by(User.username).all()


@router.post("", response_model=UserAdminOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    request: Request,
    actor: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> User:
    if payload.password.lower() == payload.username.lower():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password must not equal the username")
    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=payload.role.value,
        created_by=actor.username,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Username already exists") from exc
    db.refresh(user)
    audit.record(
        db,
        "user.create",
        actor=actor,
        target_type="user",
        target_id=user.id,
        target_name=user.username,
        ip=client_ip(request),
        detail={"role": user.role},
    )
    return user


@router.patch("/{user_id}", response_model=UserAdminOut)
def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    actor: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> User:
    target = _load(db, user_id)
    is_self = target.id == actor.id

    new_role = payload.role.value if payload.role is not None else None
    role_changes = new_role is not None and new_role != target.role
    deactivates = payload.is_active is False and target.is_active
    if is_self and (role_changes or deactivates):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "You cannot change your own role or deactivate yourself"
        )
    if is_self and payload.password is not None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Use 'change password' for your own account"
        )
    if payload.password is not None and payload.password.lower() == target.username.lower():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password must not equal the username")
    if (role_changes or deactivates) and _is_last_active_admin(db, target):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot remove the last active admin")

    changed: list[str] = []
    bump_session = False
    if role_changes:
        target.role = new_role
        changed.append("role")
        bump_session = True
    if payload.is_active is not None and payload.is_active != target.is_active:
        target.is_active = payload.is_active
        changed.append("is_active")
        bump_session = bump_session or deactivates
    if payload.password is not None:
        target.password_hash = hash_password(payload.password)
        changed.append("password")
        bump_session = True
    if bump_session:
        target.session_version += 1
    db.commit()
    db.refresh(target)

    audit.record(
        db,
        "user.update",
        actor=actor,
        target_type="user",
        target_id=target.id,
        target_name=target.username,
        ip=client_ip(request),
        detail={"changed": changed, "role": target.role, "is_active": target.is_active},
    )
    return target


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    request: Request,
    actor: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> None:
    target = _load(db, user_id)
    if target.id == actor.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot delete yourself")
    if _is_last_active_admin(db, target):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot remove the last active admin")
    name, target_id = target.username, target.id
    db.delete(target)
    db.commit()
    audit.record(
        db,
        "user.delete",
        actor=actor,
        target_type="user",
        target_id=target_id,
        target_name=name,
        ip=client_ip(request),
    )
