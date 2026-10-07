"""runs:become covers more than the run's checkbox: a run by someone without it gets
`ansible_become: false` as an extra var at execution (which outranks play, task and inventory
settings), and `ansible_become*` extra vars are refused."""

import pytest
from fastapi.testclient import TestClient

from app.db import get_sessionmaker
from app.jobs import build_job
from app.main import app
from app.models import Run
from app.routers.runs import become_vars
from tests.test_projects import _admin, _member, _populate, _project


@pytest.fixture
def world(client: TestClient):
    admin = _admin(client)
    a = _project(admin, "Team A")
    world = {"admin": admin, "a": _populate(admin, a, "a")}
    admin.worker.stop()  # new runs stay queued; the job a worker would get is built here
    return world


def _body(a: dict, **extra) -> dict:
    return {
        "playbook_id": a["playbook"],
        "inventory_id": a["inventory"],
        "credential_id": a["credential"],
        **extra,
    }


def _job_extravars(run_id: int) -> dict:
    db = get_sessionmaker()()
    try:
        return build_job(db, db.get(Run, run_id))["extravars"]
    finally:
        db.close()


@pytest.mark.parametrize(
    ("extra_vars", "flagged"),
    [
        (None, []),
        ({"greeting": "hi"}, []),
        ({"ansible_become": False}, []),
        ({"ansible_become": True}, ["ansible_become"]),
        ({"ansible_become": "yes"}, ["ansible_become"]),
        ({"ansible_become_user": "postgres"}, ["ansible_become_user"]),
        ({"ANSIBLE_BECOME_METHOD": "su"}, ["ANSIBLE_BECOME_METHOD"]),
        ({"ansible_become": False, "ansible_become_exe": "x"}, ["ansible_become_exe"]),
    ],
)
def test_which_extra_vars_count_as_become(extra_vars, flagged) -> None:
    assert become_vars(extra_vars) == flagged


def test_an_operators_run_never_becomes(world) -> None:
    a = world["a"]
    operator = _member(world["admin"], "op", {a["project"]: "operator"})
    for extra in ({"ansible_become": True}, {"ansible_become_user": "root"}):
        refused = operator.post("/api/runs", json=_body(a, extra_vars=extra))
        assert refused.status_code == 403 and "become" in refused.json()["detail"]

    run = operator.post("/api/runs", json=_body(a, extra_vars={"greeting": "hi"}))
    assert run.status_code == 201, run.text
    # Stored as typed; the job gets ansible_become: false on top.
    stored = world["admin"].get(f"/api/runs/{run.json()['id']}").json()["extra_vars"]
    assert stored == {"greeting": "hi"}
    assert _job_extravars(run.json()["id"]) == {"greeting": "hi", "ansible_become": False}

    # An explicit ansible_become: false is accepted, and run again stays blocked.
    explicit = operator.post("/api/runs", json=_body(a, extra_vars={"ansible_become": False}))
    assert explicit.status_code == 201, explicit.text
    again = operator.post(f"/api/runs/{run.json()['id']}/rerun")
    assert again.status_code == 201, again.text
    assert _job_extravars(again.json()["id"]) == {"greeting": "hi", "ansible_become": False}

    events = world["admin"].get("/api/audit", params={"action": "permission.denied"}).json()
    assert sum(e["actor_username"] == "op" for e in events["items"]) == 2


def test_a_trigger_key_never_becomes(world) -> None:
    admin, a = world["admin"], world["a"]
    token = admin.post(
        f"/api/projects/{a['project']}/api-keys",
        json={"name": "ci", "preset": "trigger", "current_password": "admin"},
    ).json()["token"]
    key = TestClient(app, headers={"Authorization": f"Bearer {token}"})
    refused = key.post("/api/runs", json=_body(a, extra_vars={"ansible_become": True}))
    assert refused.status_code == 403
    run = key.post("/api/runs", json=_body(a))
    assert run.status_code == 201, run.text
    assert _job_extravars(run.json()["id"]) == {"ansible_become": False}


def test_run_again_follows_whoever_runs_it_again(world) -> None:
    admin, a = world["admin"], world["a"]
    operator = _member(admin, "op", {a["project"]: "operator"})
    run = operator.post("/api/runs", json=_body(a, extra_vars={"greeting": "hi"})).json()
    assert _job_extravars(run["id"]) == {"greeting": "hi", "ansible_become": False}
    # An admin's run again of the operator's run may use the playbook's own become.
    again = admin.post(f"/api/runs/{run['id']}/rerun")
    assert again.status_code == 201, again.text
    assert _job_extravars(again.json()["id"]) == {"greeting": "hi"}


def test_someone_with_runs_become_keeps_the_playbooks_own_become(world) -> None:
    admin, a = world["admin"], world["a"]
    run = admin.post("/api/runs", json=_body(a, extra_vars={"greeting": "hi"}))
    assert run.status_code == 201, run.text
    assert _job_extravars(run.json()["id"]) == {"greeting": "hi"}
    explicit = admin.post("/api/runs", json=_body(a, extra_vars={"ansible_become_user": "pg"}))
    assert explicit.status_code == 201, explicit.text


def test_a_template_with_become_vars_needs_runs_become(world) -> None:
    admin, a = world["admin"], world["a"]
    operator = _member(admin, "op", {a["project"]: "operator"})
    template = {"name": "t", **_body(a), "extra_vars": {"ansible_become": True}}
    refused = operator.post("/api/run-templates", json=template)
    assert refused.status_code == 403 and "become" in refused.json()["detail"]
    saved = admin.post("/api/run-templates", json=template)
    assert saved.status_code == 201, saved.text
    # Launching the admin's template is a run by the operator: refused, like a direct run.
    launch = operator.post(f"/api/run-templates/{saved.json()['id']}/launch")
    assert launch.status_code == 403
