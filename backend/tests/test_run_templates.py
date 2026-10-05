"""Phase 5A: run templates, re-running a run, and downloading a run's log."""

import json

import pytest
from fastapi.testclient import TestClient

from app.db import get_sessionmaker
from app.models import Run, RunTemplate
from app.routers.run_templates import keep_masked
from app.routers.runs import _as_text
from app.storage import run_log_path
from tests.test_api_keys import _create_key, _key_client
from tests.test_audit import _events
from tests.test_projects import _admin, _member, _populate, _project, _template_body
from tests.test_runs import _wait_for_completion


@pytest.fixture
def world(client: TestClient):
    admin = _admin(client)
    a, b = _project(admin, "Team A"), _project(admin, "Team B")
    return {"admin": admin, "a": _populate(admin, a, "a"), "b": _populate(admin, b, "b")}


def _template(db_id: int) -> RunTemplate:
    db = get_sessionmaker()()
    try:
        return db.get(RunTemplate, db_id)
    finally:
        db.close()


def _run(run_id: int) -> Run:
    db = get_sessionmaker()()
    try:
        return db.get(Run, run_id)
    finally:
        db.close()


# ------------------------------------------------------------------ templates


def test_a_template_is_saved_listed_edited_and_deleted(world) -> None:
    admin, a = world["admin"], world["a"]
    operator = _member(admin, "op-a", {a["project"]: "operator"})
    body = _template_body(
        a,
        name="  Nightly patch  ",
        description="every night",
        group_name="g-a",
        vault_password_id=a["vault"],
        check_mode=True,
        limit=" web* ",
        extra_vars={"greeting": "hi"},
        timeout_seconds=600,
    )
    created = operator.post("/api/run-templates", json=body)
    assert created.status_code == 201, created.text
    template = created.json()
    assert template["name"] == "Nightly patch"
    assert template["project_id"] == a["project"]
    assert template["playbook_name"] == "pb-a"
    assert template["inventory_name"] == "inv-a"
    assert template["credential_name"] == "cred-a"
    assert template["vault_password_name"] == "vault-a"
    assert template["limit"] == "web*"
    assert template["extra_vars"] == {"greeting": "hi"}
    assert template["created_by"] == template["updated_by"] == "op-a"
    assert template["missing"] == []

    names = [t["name"] for t in operator.get("/api/run-templates").json()]
    assert names == ["Nightly patch", "tpl-a"]
    assert operator.get(f"/api/run-templates/{template['id']}").json()["timeout_seconds"] == 600

    updated = admin.put(
        f"/api/run-templates/{template['id']}",
        json={**body, "name": "Nightly", "vault_password_id": None, "check_mode": False},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["updated_by"] == "admin"
    assert updated.json()["vault_password_id"] is None
    assert updated.json()["missing"] == []  # removed on purpose, not deleted
    assert _template(template["id"]).uses_vault_password is False

    duplicate = operator.post("/api/run-templates", json={**body, "name": "Nightly"})
    assert duplicate.status_code == 400
    assert "already exists" in duplicate.json()["detail"]

    assert operator.delete(f"/api/run-templates/{template['id']}").status_code == 204
    assert operator.get(f"/api/run-templates/{template['id']}").status_code == 404

    actions = [
        (e["action"], e["actor_username"])
        for e in _events(admin)
        if e["target_type"] == "run_template" and e["target_id"] == template["id"]
    ]
    assert actions == [
        ("run_template.delete", "op-a"),
        ("run_template.update", "admin"),
        ("run_template.create", "op-a"),
    ]


def test_viewers_read_templates_but_never_see_their_extra_vars(world) -> None:
    admin, a = world["admin"], world["a"]
    admin.put(
        f"/api/run-templates/{a['template']}",
        json=_template_body(a, name="tpl-a", extra_vars={"greeting": "hi", "db_password": "pw"}),
    )
    viewer = _member(admin, "viewer-a", {a["project"]: "viewer"})
    shown = viewer.get(f"/api/run-templates/{a['template']}").json()
    assert shown["extra_vars"] == {"greeting": "[HIDDEN]", "db_password": "[HIDDEN]"}
    assert viewer.post("/api/run-templates", json=_template_body(a)).status_code == 403
    assert viewer.post(f"/api/run-templates/{a['template']}/launch").status_code == 403
    # people who may read extra vars still never get a secret-looking value back
    assert admin.get(f"/api/run-templates/{a['template']}").json()["extra_vars"] == {
        "greeting": "hi",
        "db_password": "[REDACTED]",
    }


def test_editing_a_template_keeps_secrets_sent_back_masked(world) -> None:
    admin, a = world["admin"], world["a"]
    extra = {"greeting": "hi", "db_password": "s3cret", "nested": {"api_token": "t0ken"}}
    admin.put(
        f"/api/run-templates/{a['template']}",
        json=_template_body(a, name="tpl-a", extra_vars=extra),
    )
    shown = admin.get(f"/api/run-templates/{a['template']}").json()["extra_vars"]
    assert shown["db_password"] == shown["nested"]["api_token"] == "[REDACTED]"

    shown["greeting"] = "hello"
    response = admin.put(
        f"/api/run-templates/{a['template']}",
        json=_template_body(a, name="tpl-a", extra_vars=shown),
    )
    assert response.status_code == 200, response.text
    assert _template(a["template"]).extra_vars == {
        "greeting": "hello",
        "db_password": "s3cret",
        "nested": {"api_token": "t0ken"},
    }

    # a changed secret is stored as sent
    shown["db_password"] = "rotated"
    admin.put(
        f"/api/run-templates/{a['template']}",
        json=_template_body(a, name="tpl-a", extra_vars=shown),
    )
    assert _template(a["template"]).extra_vars["db_password"] == "rotated"


def test_keep_masked_only_restores_the_same_place() -> None:
    stored = {"a_password": "x", "items": [{"token": "t"}], "plain": "p"}
    shown = {"a_password": "[REDACTED]", "items": [{"token": "[REDACTED]"}], "plain": "p"}
    assert keep_masked(shown, stored, shown) == stored
    # moved to another key: the mask stays a mask
    assert keep_masked({"other": "[REDACTED]"}, stored, shown) == {"other": "[REDACTED]"}
    # a list of another length isn't matched up element by element
    sent = {"items": [{"token": "[REDACTED]"}, {"token": "[REDACTED]"}]}
    assert keep_masked(sent, stored, shown) == sent
    assert keep_masked({"plain": "q"}, stored, shown) == {"plain": "q"}


def test_template_references_must_be_in_the_playbooks_project(world) -> None:
    admin, a, b = world["admin"], world["a"], world["b"]
    for field, key in (
        ("inventory_id", "inventory"),
        ("credential_id", "credential"),
        ("vault_password_id", "vault"),
    ):
        response = admin.post("/api/run-templates", json=_template_body(a, **{field: b[key]}))
        assert response.status_code == 400, (field, response.text)
        assert "same project" in response.json()["detail"]
    moved = admin.put(
        f"/api/run-templates/{a['template']}",
        json=_template_body(b, name="tpl-a"),
    )
    assert moved.status_code == 400
    assert "template's project" in moved.json()["detail"]

    only_a = _member(admin, "only-a", {a["project"]: "operator"})
    response = only_a.post(
        "/api/run-templates", json=_template_body(a, credential_id=b["credential"])
    )
    assert response.status_code == 404  # B's credential doesn't exist for this caller


def test_saving_or_launching_a_become_template_needs_become(world) -> None:
    admin, a = world["admin"], world["a"]
    operator = _member(admin, "op-a", {a["project"]: "operator"})
    refused = operator.post("/api/run-templates", json=_template_body(a, become=True))
    assert refused.status_code == 403
    assert "become" in refused.json()["detail"]
    denied = [
        e for e in _events(admin, action="permission.denied") if e["actor_username"] == "op-a"
    ]
    assert denied and denied[0]["detail"] == {"required": "runs:become"}

    created = admin.post("/api/run-templates", json=_template_body(a, name="root", become=True))
    assert created.status_code == 201, created.text
    assert created.json()["become"] is True
    launch = operator.post(f"/api/run-templates/{created.json()['id']}/launch")
    assert launch.status_code == 403
    assert "become" in launch.json()["detail"]
    # nor can an operator edit someone else's become template while keeping become
    edit = operator.put(
        f"/api/run-templates/{created.json()['id']}",
        json=_template_body(a, name="root", become=True),
    )
    assert edit.status_code == 403


def test_launching_a_template_starts_its_run_with_overrides(world) -> None:
    admin, a = world["admin"], world["a"]
    operator = _member(admin, "op-a", {a["project"]: "operator"})
    template = operator.post(
        "/api/run-templates",
        json=_template_body(
            a, name="greet", diff_mode=True, limit="h-a", extra_vars={"greeting": "hey"}
        ),
    ).json()

    launched = operator.post(f"/api/run-templates/{template['id']}/launch")
    assert launched.status_code == 201, launched.text
    run = launched.json()
    assert (run["playbook_id"], run["inventory_id"], run["credential_id"]) == (
        a["playbook"],
        a["inventory"],
        a["credential"],
    )
    assert run["diff_mode"] is True and run["check_mode"] is False
    assert run["limit"] == "h-a"
    assert run["extra_vars"] == {"greeting": "hey"}
    assert run["triggered_by"] == "op-a"
    assert _wait_for_completion(operator, run["id"])["status"] == "success"

    overridden = operator.post(
        f"/api/run-templates/{template['id']}/launch", json={"limit": "  ", "check_mode": True}
    ).json()
    assert overridden["limit"] is None  # blank clears the template's limit for this run
    assert overridden["check_mode"] is True
    _wait_for_completion(operator, overridden["id"])

    trigger = next(e for e in _events(admin, action="run.trigger") if e["target_id"] == run["id"])
    assert trigger["detail"]["template"] == "greet"
    assert trigger["detail"]["template_id"] == template["id"]


def test_a_template_whose_item_was_deleted_says_so_and_refuses_to_launch(world) -> None:
    admin, a = world["admin"], world["a"]
    template = admin.post(
        "/api/run-templates", json=_template_body(a, name="vaulted", vault_password_id=a["vault"])
    ).json()
    assert admin.delete(f"/api/vault-passwords/{a['vault']}").status_code == 204
    shown = admin.get(f"/api/run-templates/{template['id']}").json()
    assert shown["missing"] == ["vault password"]
    refused = admin.post(f"/api/run-templates/{template['id']}/launch")
    assert refused.status_code == 409
    assert refused.json()["detail"] == (
        "Template 'vaulted' can't be started: its vault password has been deleted"
    )

    assert admin.delete(f"/api/playbooks/{a['playbook']}").status_code == 204
    assert admin.get(f"/api/run-templates/{template['id']}").json()["missing"] == [
        "playbook",
        "vault password",
    ]
    assert (
        "have been deleted"
        in admin.post(f"/api/run-templates/{template['id']}/launch").json()["detail"]
    )


def test_deleting_a_project_deletes_its_templates(world) -> None:
    # A project is deleted once its content is gone; a template whose items went with it
    # goes with the project.
    admin = world["admin"]
    empty = _project(admin, "Team C")
    db = get_sessionmaker()()
    template = RunTemplate(project_id=empty, name="left over", created_by="x", updated_by="x")
    db.add(template)
    db.commit()
    template_id = template.id
    db.close()
    assert admin.delete(f"/api/projects/{empty}").status_code == 204
    assert _template(template_id) is None


# ------------------------------------------------------------------ API keys


def test_a_trigger_key_launches_a_template_and_downloads_the_log(world) -> None:
    admin, a, b = world["admin"], world["a"], world["b"]
    key = _key_client(_create_key(admin, a["project"], name="ci")["token"])
    launched = key.post(f"/api/run-templates/{a['template']}/launch", json={"check_mode": True})
    assert launched.status_code == 201, launched.text
    assert launched.json()["triggered_by"] == "apikey:ci"
    run = _wait_for_completion(key, launched.json()["id"])
    assert run["status"] == "success"
    log = key.get(f"/api/runs/{run['id']}/log")
    assert log.status_code == 200
    assert "PLAY RECAP" in log.text

    # not another project's template, and not the template routes themselves
    assert key.post(f"/api/run-templates/{b['template']}/launch").status_code == 404
    assert key.get("/api/run-templates").status_code == 403
    assert key.post(f"/api/runs/{a['run']}/rerun").status_code == 403

    read_only = _key_client(
        _create_key(admin, a["project"], name="ro", preset="read-only")["token"]
    )
    assert read_only.post(f"/api/run-templates/{a['template']}/launch").status_code == 403
    assert read_only.get(f"/api/runs/{a['run']}/log?format=jsonl").status_code == 200


# ------------------------------------------------------------------ re-run


def test_run_again_repeats_the_run_with_its_extra_vars(world) -> None:
    admin, a = world["admin"], world["a"]
    operator = _member(admin, "op-a", {a["project"]: "operator"})
    original = operator.post(
        "/api/runs",
        json={
            "playbook_id": a["playbook"],
            "inventory_id": a["inventory"],
            "group_name": "g-a",
            "credential_id": a["credential"],
            "vault_password_id": a["vault"],
            "check_mode": True,
            "limit": "h-a",
            "extra_vars": {"greeting": "again", "db_password": "pw"},
            "timeout_seconds": 300,
        },
    ).json()
    _wait_for_completion(operator, original["id"])

    again = operator.post(f"/api/runs/{original['id']}/rerun")
    assert again.status_code == 201, again.text
    copy = again.json()
    assert copy["id"] != original["id"]
    for field in (
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
        assert copy[field] == original[field], field
    assert copy["triggered_by"] == "op-a"
    assert _run(copy["id"]).extra_vars == {"greeting": "again", "db_password": "pw"}
    _wait_for_completion(operator, copy["id"])

    trigger = next(e for e in _events(admin, action="run.trigger") if e["target_id"] == copy["id"])
    assert trigger["detail"]["rerun_of"] == original["id"]


def test_run_again_is_refused_when_something_it_used_was_deleted(world) -> None:
    admin, a = world["admin"], world["a"]
    assert admin.delete(f"/api/credentials/{a['credential']}").status_code == 204
    refused = admin.post(f"/api/runs/{a['run']}/rerun")
    assert refused.status_code == 409
    assert refused.json()["detail"] == (
        f"Run #{a['run']} can't be started: its credential has been deleted"
    )
    assert admin.get(f"/api/runs/{a['run']}").json()["credential_id"] is None


def test_run_again_needs_the_same_permissions_as_the_run(world) -> None:
    admin, a = world["admin"], world["a"]
    viewer = _member(admin, "viewer-a", {a["project"]: "viewer"})
    assert viewer.post(f"/api/runs/{a['run']}/rerun").status_code == 403

    db = get_sessionmaker()()
    db.get(Run, a["run"]).become = True
    db.commit()
    db.close()
    operator = _member(admin, "op-a", {a["project"]: "operator"})
    refused = operator.post(f"/api/runs/{a['run']}/rerun")
    assert refused.status_code == 403
    assert "become" in refused.json()["detail"]


# ------------------------------------------------------------------ log download


def test_the_log_downloads_as_text_or_json_lines(world) -> None:
    admin, a = world["admin"], world["a"]
    viewer = _member(admin, "viewer-a", {a["project"]: "viewer"})

    text = viewer.get(f"/api/runs/{a['run']}/log")
    assert text.status_code == 200
    assert text.headers["content-type"] == "text/plain; charset=utf-8"
    assert text.headers["content-disposition"] == (
        f'attachment; filename="ansideck-run-{a["run"]}.log"'
    )
    assert "PLAY RECAP" in text.text
    assert "\x1b" not in text.text

    lines = viewer.get(f"/api/runs/{a['run']}/log", params={"format": "jsonl"})
    assert lines.headers["content-type"] == "application/x-ndjson"
    assert lines.headers["content-disposition"].endswith(f'ansideck-run-{a["run"]}.jsonl"')
    events = [json.loads(line) for line in lines.text.splitlines()]
    assert events and all("counter" in e for e in events)
    assert lines.content == run_log_path(a["run"]).read_bytes()

    assert viewer.get(f"/api/runs/{a['run']}/log", params={"format": "html"}).status_code == 422


def test_the_log_download_stops_at_what_was_committed(world) -> None:
    admin, a = world["admin"], world["a"]
    path = run_log_path(a["run"])
    committed = path.read_bytes()
    with path.open("ab") as log:  # a write whose commit never happened
        log.write(json.dumps({"counter": 999, "stdout": "UNCOMMITTED"}).encode() + b"\n")
    for fmt in ("text", "jsonl"):
        body = admin.get(f"/api/runs/{a['run']}/log", params={"format": fmt})
        assert "UNCOMMITTED" not in body.text, fmt
    assert admin.get(f"/api/runs/{a['run']}/log?format=jsonl").content == committed


def test_a_queued_run_downloads_an_empty_log(world) -> None:
    admin, a = world["admin"], world["a"]
    db = get_sessionmaker()()
    run = db.get(Run, a["run"])
    run.log_bytes = 0
    db.commit()
    db.close()
    run_log_path(a["run"]).unlink()
    for fmt in ("text", "jsonl"):
        response = admin.get(f"/api/runs/{a['run']}/log", params={"format": fmt})
        assert response.status_code == 200
        assert response.content == b""


def test_text_export_strips_colour_codes_and_skips_events_without_output() -> None:
    lines = [
        json.dumps({"counter": 1, "stdout": "\x1b[0;32mok: [web1]\x1b[0m"}).encode() + b"\n",
        json.dumps({"counter": 2, "stdout": ""}).encode() + b"\n",
        json.dumps({"counter": 3}).encode() + b"\n",
        b"not json\n",
        json.dumps(["not", "an", "event"]).encode() + b"\n",
        json.dumps({"counter": 4, "stdout": "a\r\nb \x1b]8;;http://x\x07link\x1b]8;;\x07"}).encode()
        + b"\n",
    ]
    assert b"".join(_as_text(iter(lines))) == b"ok: [web1]\na\nb link\n"
