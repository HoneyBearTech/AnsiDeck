"""Run templates (Phase 5A): a saved playbook + inventory (and target group) + credential +
options, launched again in one step, from the UI or by a CI/CD key."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.hardening import client_ip
from app.models import (
    Credential,
    Inventory,
    Playbook,
    RunTemplate,
    User,
    VaultPassword,
)
from app.permissions import Permission, Scope, guard, project_permissions
from app.routers.runs import HIDDEN, _run_out, deleted_items_conflict, queue_run
from app.schemas.run_templates import RunTemplateIn, RunTemplateLaunch, RunTemplateOut
from app.schemas.runs import RunCreate, RunOut
from app.scoping import deny, get_scoped, readable_project_ids

router = APIRouter()

_guard = guard(Permission.CONTENT_READ, Permission.CONTENT_WRITE, scope=Scope.PROJECT)
# Launching is starting a run: trigger keys may do it (a test pins the API-key routes).
_launch_guard = guard(
    Permission.CONTENT_READ, Permission.RUNS_TRIGGER, scope=Scope.PROJECT, api_key=True
)


def _missing(template: RunTemplate) -> list[str]:
    missing = [
        label
        for label, ref in (
            ("playbook", template.playbook_id),
            ("inventory", template.inventory_id),
            ("credential", template.credential_id),
        )
        if ref is None
    ]
    if template.uses_vault_password and template.vault_password_id is None:
        missing.append("vault password")
    return missing


def _name(db: Session, model: type[Any], obj_id: int | None) -> str | None:
    obj = db.get(model, obj_id) if obj_id is not None else None
    return obj.name if obj is not None else None


def _out(db: Session, template: RunTemplate, user: User) -> RunTemplateOut:
    out = RunTemplateOut.model_validate(template)
    out.playbook_name = _name(db, Playbook, template.playbook_id)
    out.inventory_name = _name(db, Inventory, template.inventory_id)
    out.credential_name = _name(db, Credential, template.credential_id)
    out.vault_password_name = _name(db, VaultPassword, template.vault_password_id)
    out.missing = _missing(template)
    can_see = Permission.RUNS_READ_EXTRA_VARS in project_permissions(db, user, template.project_id)
    if out.extra_vars and not can_see:
        out.extra_vars = dict.fromkeys(out.extra_vars, HIDDEN)
    return out


def keep_masked(sent: Any, stored: Any, shown: Any) -> Any:
    """Extra vars sent back as they were shown (a secret-looking value masked, or one hidden)
    keep the stored value there, so editing a template doesn't overwrite its secrets with the
    mask. Only the same place is restored: nothing stored can be moved or read this way."""
    if isinstance(sent, dict) and isinstance(stored, dict) and isinstance(shown, dict):
        return {
            k: keep_masked(v, stored[k], shown[k]) if k in stored and k in shown else v
            for k, v in sent.items()
        }
    if (
        isinstance(sent, list)
        and isinstance(stored, list)
        and isinstance(shown, list)
        and len(sent) == len(stored) == len(shown)
    ):
        return [keep_masked(*values) for values in zip(sent, stored, shown, strict=True)]
    if sent == shown and sent != stored:
        return stored
    return sent


def _check_references(
    db: Session, user: User, request: Request, payload: RunTemplateIn, project_id: int
) -> None:
    """Everything the template names must be in its project and usable by its author."""
    for model, obj_id, permission, label in (
        (Inventory, payload.inventory_id, Permission.CONTENT_READ, "Inventory"),
        (Credential, payload.credential_id, Permission.SECRETS_LIST, "Credential"),
        (VaultPassword, payload.vault_password_id, Permission.SECRETS_LIST, "Vault password"),
    ):
        if obj_id is None:
            continue
        obj = get_scoped(db, user, request, model, obj_id, permission, f"{label} not found")
        if obj.project_id != project_id:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"{label} must belong to the same project as the playbook",
            )
        if model is Credential and obj.kind != "ssh":
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "A run needs an SSH key credential")
    if payload.become and Permission.RUNS_BECOME not in project_permissions(db, user, project_id):
        deny(db, user, request, Permission.RUNS_BECOME, project_id)  # audits the refusal
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "You may not save a template that runs as root (become)"
        )


def _apply(template: RunTemplate, payload: RunTemplateIn, extra_vars: dict | None) -> None:
    for field in (
        "name",
        "description",
        "playbook_id",
        "inventory_id",
        "group_name",
        "credential_id",
        "vault_password_id",
        "become",
        "check_mode",
        "diff_mode",
        "limit",
        "timeout_seconds",
    ):
        setattr(template, field, getattr(payload, field))
    template.uses_vault_password = payload.vault_password_id is not None
    template.extra_vars = extra_vars


def _save(db: Session) -> None:
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "A template with this name already exists in the project"
        ) from exc


def _record(
    db: Session,
    action: str,
    user: User,
    request: Request,
    target: tuple[int, str, int],
    detail: dict | None = None,
) -> None:
    template_id, name, project_id = target
    audit.record(
        db,
        f"run_template.{action}",
        actor=user,
        target_type="run_template",
        target_id=template_id,
        target_name=name,
        ip=client_ip(request),
        project_id=project_id,
        detail=detail,
    )


def _target(template: RunTemplate) -> tuple[int, str, int]:
    return template.id, template.name, template.project_id


def _detail(template: RunTemplate) -> dict:
    return {
        "playbook": template.playbook_id,
        "inventory": template.inventory_id,
        "become": template.become,
    }


@router.get("", response_model=list[RunTemplateOut])
def list_templates(
    request: Request,
    project_id: int | None = Query(None),
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> list[RunTemplateOut]:
    ids = readable_project_ids(db, user, request, Permission.CONTENT_READ, project_id)
    query = db.query(RunTemplate)
    if ids is not None:
        query = query.filter(RunTemplate.project_id.in_(ids))
    return [_out(db, t, user) for t in query.order_by(RunTemplate.name, RunTemplate.id).all()]


@router.get("/{template_id}", response_model=RunTemplateOut)
def get_template(
    template_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> RunTemplateOut:
    template = get_scoped(
        db, user, request, RunTemplate, template_id, Permission.CONTENT_READ, "Template not found"
    )
    return _out(db, template, user)


@router.post("", response_model=RunTemplateOut, status_code=status.HTTP_201_CREATED)
def create_template(
    payload: RunTemplateIn,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> RunTemplateOut:
    # The playbook fixes the template's project (as it does a run's).
    playbook = get_scoped(
        db, user, request, Playbook, payload.playbook_id, Permission.CONTENT_WRITE,
        "Playbook not found",
    )  # fmt: skip
    _check_references(db, user, request, payload, playbook.project_id)
    template = RunTemplate(
        project_id=playbook.project_id, created_by=user.username, updated_by=user.username
    )
    _apply(template, payload, payload.extra_vars)
    db.add(template)
    _save(db)
    db.refresh(template)
    _record(db, "create", user, request, _target(template), _detail(template))
    return _out(db, template, user)


@router.put("/{template_id}", response_model=RunTemplateOut)
def update_template(
    template_id: int,
    payload: RunTemplateIn,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> RunTemplateOut:
    template = get_scoped(
        db, user, request, RunTemplate, template_id, Permission.CONTENT_WRITE,
        "Template not found",
    )  # fmt: skip
    playbook = get_scoped(
        db, user, request, Playbook, payload.playbook_id, Permission.CONTENT_WRITE,
        "Playbook not found",
    )  # fmt: skip
    if playbook.project_id != template.project_id:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "The playbook must belong to the template's project"
        )
    _check_references(db, user, request, payload, template.project_id)
    stored = template.extra_vars
    extra_vars = payload.extra_vars
    if extra_vars is not None and stored is not None:
        shown = _out(db, template, user).extra_vars
        extra_vars = keep_masked(extra_vars, stored, shown)
    _apply(template, payload, extra_vars)
    template.updated_by = user.username
    _save(db)
    db.refresh(template)
    _record(db, "update", user, request, _target(template), _detail(template))
    return _out(db, template, user)


@router.delete("/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_template(
    template_id: int,
    request: Request,
    user: User = Depends(_guard),
    db: Session = Depends(get_db),
) -> None:
    template = get_scoped(
        db, user, request, RunTemplate, template_id, Permission.CONTENT_WRITE,
        "Template not found",
    )  # fmt: skip
    target = _target(template)
    db.delete(template)
    db.commit()
    _record(db, "delete", user, request, target)


@router.post("/{template_id}/launch", response_model=RunOut, status_code=status.HTTP_201_CREATED)
def launch_template(
    template_id: int,
    request: Request,
    payload: RunTemplateLaunch | None = None,
    user: User = Depends(_launch_guard),
    db: Session = Depends(get_db),
) -> RunOut:
    """Starts a run from the template, as its items are now. `limit` and `check_mode` may be
    changed for this run only. The caller needs the same permissions as for starting the run
    directly (become included)."""
    template = get_scoped(
        db, user, request, RunTemplate, template_id, Permission.RUNS_TRIGGER, "Template not found"
    )
    if missing := _missing(template):
        raise deleted_items_conflict(f"Template {template.name!r}", missing)
    overrides = payload or RunTemplateLaunch()
    run_request = RunCreate(
        playbook_id=template.playbook_id,
        inventory_id=template.inventory_id,
        group_name=template.group_name,
        credential_id=template.credential_id,
        vault_password_id=template.vault_password_id,
        become=template.become,
        check_mode=(template.check_mode if overrides.check_mode is None else overrides.check_mode),
        diff_mode=template.diff_mode,
        limit=template.limit if overrides.limit is None else overrides.limit,
        extra_vars=template.extra_vars,
        timeout_seconds=template.timeout_seconds,
    )
    run = queue_run(
        db,
        user,
        request,
        run_request,
        audit_detail={"template": template.name, "template_id": template.id},
    )
    return _run_out(db, run, user)
