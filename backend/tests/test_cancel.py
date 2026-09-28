"""Cancel, the reasons a queued run is still waiting, the worker registry, and a queued galaxy
install's wait."""

import pytest
from sqlalchemy import text, update

from app.db import get_engine, get_sessionmaker
from app.models import AuditEvent, GalaxyInstall, Worker
from app.reaper import reap_once
from app.worker.client import ApiClient
from app.worker.runner import Worker as WorkerProcess
from tests.conftest import _NoTimeout, internal_client, make_user_client
from tests.test_internal_api import Claimed
from tests.test_projects import _member, _project
from tests.test_queue import _claim, _queue_runs
from tests.test_reaper import _same_run
from tests.test_runs import _login

pytestmark = pytest.mark.no_worker  # these tests play the worker themselves


def _audit(action: str) -> list[AuditEvent]:
    db = get_sessionmaker()()
    try:
        return db.query(AuditEvent).filter(AuditEvent.action == action).all()
    finally:
        db.close()


def _heartbeat(worker_id: str, slots: int = 1, runs: list | None = None):
    response = internal_client().post(
        "/internal/heartbeat", json={"worker_id": worker_id, "slots": slots, "runs": runs or []}
    )
    assert response.status_code == 200
    return response.json()["runs"]


def _waiting(client, run_id: int) -> str | None:
    return client.get(f"/api/runs/{run_id}").json()["waiting_reason"]


# ------------------------------------------------------------------ cancel


def test_a_queued_run_is_cancelled_at_once_and_its_inventory_moves_on(client, tmp_path) -> None:
    [[first, second]] = _queue_runs(client, 1, 2).values()

    response = client.post(f"/api/runs/{first}/cancel")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "cancelled"
    assert body["status_reason"] == "cancelled by admin before it started"
    assert body["cancel_requested_by"] == "admin" and body["finished_at"] is not None
    log = (tmp_path / "runs" / f"{first}.jsonl").read_text().splitlines()
    assert len(log) == 1 and "cancelled by admin before it started" in log[0]
    [event] = _audit("run.cancel")
    assert (event.target_id, event.actor_username, event.detail) == (
        first,
        "admin",
        {"was": "queued"},
    )

    assert _claim().run_id == second  # the FIFO rule no longer waits for it
    finished = client.post(f"/api/runs/{first}/cancel")
    assert finished.status_code == 409
    assert "already finished (cancelled)" in finished.json()["detail"]


def test_a_running_run_is_marked_and_its_worker_told_to_stop(client) -> None:
    claimed = Claimed(client)
    assert claimed.job().status_code == 200

    response = client.post(f"/api/runs/{claimed.run_id}/cancel")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "running"
    assert body["cancel_requested_at"] is not None and body["cancel_requested_by"] == "admin"
    [event] = _audit("run.cancel")
    assert event.detail == {"was": "running"}

    # The worker hears it on its next heartbeat or event batch.
    hb = _heartbeat("w", runs=[{"run_id": claimed.run_id, "claim_token": claimed.claim_token}])
    assert hb == [{"run_id": claimed.run_id, "state": "cancel"}]
    assert claimed.events(1, 1).json() == {"acked_seq": 1, "cancel": True}

    # Asking again changes nothing (and isn't audited twice).
    again = client.post(f"/api/runs/{claimed.run_id}/cancel").json()
    assert again["cancel_requested_at"] == body["cancel_requested_at"]
    assert len(_audit("run.cancel")) == 1

    assert claimed.complete(1, "cancelled").status_code == 200
    row = claimed.row()
    assert (row.status, row.status_reason) == ("cancelled", "cancelled by admin")
    assert client.post(f"/api/runs/{claimed.run_id}/cancel").status_code == 409


def test_a_run_cancelled_between_its_claim_and_its_job_never_starts(client) -> None:
    claimed = Claimed(client)
    assert client.post(f"/api/runs/{claimed.run_id}/cancel").status_code == 200
    assert claimed.job().status_code == 410  # no secrets handed out
    row = claimed.row()
    assert (row.status, row.status_reason, row.started_at) == (
        "cancelled",
        "cancelled before it started",
        None,
    )


def test_cancel_needs_runs_trigger_in_the_runs_project(client) -> None:
    [[run_id]] = _queue_runs(client, 1, 1).values()
    viewer = make_user_client("viewer1", "viewer")
    # An operator elsewhere can't even tell the run exists.
    outsider = _member(client, "outsider", {_project(client, "Other"): "operator"})
    operator = make_user_client("operator1", "operator")

    assert viewer.post(f"/api/runs/{run_id}/cancel").status_code == 403
    assert outsider.post(f"/api/runs/{run_id}/cancel").status_code == 404
    assert client.post("/api/runs/999999/cancel").status_code == 404
    denied = [e for e in _audit("permission.denied") if e.actor_username == "viewer1"]
    assert denied and denied[0].detail == {"required": "runs:trigger"}

    response = operator.post(f"/api/runs/{run_id}/cancel")
    assert response.status_code == 200
    assert response.json()["cancel_requested_by"] == "operator1"


# ------------------------------------------------------------------ why a run waits


def test_a_queued_run_says_what_it_is_waiting_for(client) -> None:
    queued = _queue_runs(client, 2, 1)
    (inv_a, [run_a]), (inv_b, [run_b]) = queued.items()
    assert _waiting(client, run_a) == "No worker is online: start one to run queued runs"

    _heartbeat("w", slots=1)
    assert _waiting(client, run_a) == "Waiting for a worker…"

    assert _claim("w").run_id == run_a  # its one slot is now busy
    assert _waiting(client, run_b) == "Waiting for a free worker (all are busy)"
    _heartbeat("w", slots=2)
    assert _waiting(client, run_b) == "Waiting for a worker…"

    behind_running = client.post("/api/runs", json=_same_run(client, run_a)).json()["id"]
    behind_queued = client.post("/api/runs", json=_same_run(client, run_a)).json()["id"]
    assert _waiting(client, behind_running) == f"Waiting behind run #{run_a} (same inventory)"
    assert (
        _waiting(client, behind_queued) == f"Waiting behind run #{behind_running} (same inventory)"
    )

    db = get_sessionmaker()()
    db.add(GalaxyInstall(status="queued", triggered_by="admin", requirements_snapshot="x"))
    db.commit()
    db.close()
    assert _waiting(client, run_b) == "Waiting for a galaxy install to finish"

    # Only a single run's page carries it (the list would cost queries per row), and only while
    # the run is queued.
    assert all(r["waiting_reason"] is None for r in client.get("/api/runs").json())
    assert _waiting(client, run_a) is None


def test_a_worker_that_is_gone_no_longer_counts_as_online(client) -> None:
    [[run_id]] = _queue_runs(client, 1, 1).values()
    _heartbeat("w")
    with get_engine().begin() as conn:
        conn.execute(update(Worker).values(last_seen_at=text("now() - interval '31 seconds'")))
    assert _waiting(client, run_id) == "No worker is online: start one to run queued runs"


# ------------------------------------------------------------------ worker registry


def test_workers_report_in_by_claiming_and_heartbeating(client) -> None:
    _queue_runs(client, 1, 1)
    claim = internal_client().post(
        "/internal/claim", json={"worker_id": "host-a:1", "slots": 3, "wait_seconds": 0}
    )
    assert claim.status_code == 200
    _heartbeat("host-b:2", slots=2)
    _heartbeat("host-c:3")
    with get_engine().begin() as conn:
        conn.execute(
            update(Worker)
            .where(Worker.id == "host-c:3")
            .values(last_seen_at=text("now() - interval '5 minutes'"))
        )

    workers = client.get("/api/workers").json()
    # Most recently seen first.
    assert [(w["id"], w["slots"], w["running"], w["online"]) for w in workers] == [
        ("host-b:2", 2, 0, True),
        ("host-a:1", 3, 1, True),
        ("host-c:3", 1, 0, False),
    ]
    assert make_user_client("operator1", "operator").get("/api/workers").status_code == 403


def test_the_reaper_forgets_workers_not_seen_for_a_day(client) -> None:
    _heartbeat("old")
    _heartbeat("recent")
    with get_engine().begin() as conn:
        conn.execute(
            update(Worker)
            .where(Worker.id == "old")
            .values(last_seen_at=text("now() - interval '25 hours'"))
        )
    reap_once()
    _login(client)
    assert [w["id"] for w in client.get("/api/workers").json()] == ["recent"]


def test_an_idle_worker_still_heartbeats(client, tmp_path) -> None:
    worker = WorkerProcess(
        ApiClient(_NoTimeout(internal_client())), worker_id="idle:1", slots=2, galaxy_dir=tmp_path
    )
    worker.beat()  # no runs
    db = get_sessionmaker()()
    try:
        assert db.get(Worker, "idle:1").slots == 2
    finally:
        db.close()


# ------------------------------------------------------------------ galaxy


def test_a_queued_install_says_how_many_runs_it_waits_for(client) -> None:
    Claimed(client)
    db = get_sessionmaker()()
    install = GalaxyInstall(status="queued", triggered_by="admin", requirements_snapshot="x")
    done = GalaxyInstall(status="success", triggered_by="admin", requirements_snapshot="x")
    db.add_all([install, done])
    db.commit()
    install_id, done_id = install.id, done.id
    db.close()

    listed = {i["id"]: i["waiting_for_runs"] for i in client.get("/api/galaxy/installs").json()}
    assert listed == {install_id: 1, done_id: None}
    assert client.get(f"/api/galaxy/installs/{install_id}").json()["waiting_for_runs"] == 1
