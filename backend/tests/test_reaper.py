import pytest
from sqlalchemy import text, update

from app.db import get_engine, get_sessionmaker
from app.models import AuditEvent, Credential, GalaxyInstall, Run
from app.reaper import reap_once
from tests.test_internal_api import Claimed

pytestmark = pytest.mark.no_worker


def _set(run_id: int, **values) -> None:
    with get_engine().begin() as conn:
        conn.execute(update(Run).where(Run.id == run_id).values(**values))


def _audit(action: str) -> list[AuditEvent]:
    db = get_sessionmaker()()
    try:
        return db.query(AuditEvent).filter(AuditEvent.action == action).all()
    finally:
        db.close()


def test_healthy_runs_are_left_alone(client) -> None:
    claimed = Claimed(client)
    assert reap_once() == []
    assert claimed.row().status == "running"


def test_a_run_whose_worker_stopped_heartbeating_is_failed_and_its_inventory_freed(
    client, tmp_path
) -> None:
    claimed = Claimed(client)
    claimed.events(1, 2)
    _set(claimed.run_id, lease_expires_at=text("now() - interval '1 second'"))

    assert reap_once() == [claimed.run_id]
    row = claimed.row()
    assert row.status == "failed"
    assert row.status_reason.startswith("worker lost: no heartbeat from w since ")
    assert row.finished_at is not None and row.claim_token_hash is None
    log = (tmp_path / "runs" / f"{claimed.run_id}.jsonl").read_text().splitlines()
    assert len(log) == 3 and "worker lost" in log[-1]  # after the worker's own lines
    assert row.log_seq == 3
    [event] = _audit("run.worker_lost")
    assert (event.target_id, event.actor_username) == (claimed.run_id, "w")

    # The worker, if it ever comes back, can no longer write to the run...
    assert claimed.events(3, 1).status_code == 410
    # ...and the inventory is free for the next run.
    second = client.post("/api/runs", json=_same_run(client, claimed.run_id)).json()["id"]
    http = claimed.http
    claim = http.post("/internal/claim", json={"worker_id": "w2", "wait_seconds": 0}).json()
    assert claim["run_id"] == second


def _same_run(client, run_id: int) -> dict:
    db = get_sessionmaker()()
    run = db.get(Run, run_id)
    db.close()
    return {
        "playbook_id": run.playbook_id,
        "inventory_id": run.inventory_id,
        "credential_id": run.credential_id,
    }


def test_a_run_past_its_timeout_is_timed_out_if_its_worker_did_not(client) -> None:
    claimed = Claimed(client)
    claimed.job()
    _set(claimed.run_id, timeout_seconds=60, started_at=text("now() - interval '181 seconds'"))
    assert reap_once() == [claimed.run_id]
    row = claimed.row()
    assert row.status == "timed_out"
    assert row.status_reason == "timed out after 60 s (its worker did not stop it)"
    assert len(_audit("run.timed_out")) == 1


def test_a_cancel_the_worker_never_confirmed_is_applied(client) -> None:
    claimed = Claimed(client)
    _set(
        claimed.run_id,
        cancel_requested_at=text("now() - interval '91 seconds'"),
        cancel_requested_by="alice",
    )
    assert reap_once() == [claimed.run_id]
    row = claimed.row()
    assert (row.status, row.status_reason) == (
        "cancelled",
        "cancelled by alice (its worker did not confirm)",
    )


def test_a_queued_run_whose_credential_was_deleted_is_failed(client) -> None:
    claimed = Claimed(client)  # the first run holds the inventory; the next one queues
    second = client.post("/api/runs", json=_same_run(client, claimed.run_id)).json()["id"]
    db = get_sessionmaker()()
    db.query(Run).filter(Run.id == claimed.run_id).update({Run.credential_id: None})
    db.query(Credential).delete()
    db.commit()
    db.close()

    reaped = reap_once()
    assert second in reaped
    run = client.get(f"/api/runs/{second}").json()
    assert (run["status"], run["status_reason"]) == (
        "failed",
        "not run: its credential was deleted",
    )


def test_an_install_whose_process_went_away_is_failed(client) -> None:
    db = get_sessionmaker()()
    install = GalaxyInstall(
        status="running",
        triggered_by="admin",
        requirements_snapshot="x",
        lease_expires_at=text("now() - interval '1 second'"),
    )
    db.add(install)
    db.commit()
    reap_once()
    db.refresh(install)
    assert install.status == "failed"
    assert install.status_reason == "interrupted: the API process running it went away"
    db.close()
