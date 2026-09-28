import threading
import time
from collections import defaultdict

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text, update

from app.db import GALAXY_GATE_KEY, get_engine, get_sessionmaker
from app.galaxy import try_start_install
from app.models import GalaxyInstall, InventoryGroup, Run
from app.queue import claim_next
from tests.conftest import internal_client
from tests.test_runs import (
    SUCCESS_PLAYBOOK,
    _create_credential,
    _create_inventory_with_host,
    _create_playbook,
    _login,
)

pytestmark = pytest.mark.no_worker  # these tests claim runs themselves


def _queue_runs(client: TestClient, inventories: int, per_inventory: int) -> dict[int, list[int]]:
    """{inventory_id: [run ids in the order they were queued]}"""
    _login(client)
    playbook_id = _create_playbook(client, SUCCESS_PLAYBOOK)
    credential_id = _create_credential(client)
    inventory_ids = [
        _create_inventory_with_host(client, "/dev/null", name=f"inv-{n}")[0]
        for n in range(inventories)
    ]
    queued: dict[int, list[int]] = defaultdict(list)
    for _ in range(per_inventory):
        for inventory_id in inventory_ids:
            response = client.post(
                "/api/runs",
                json={
                    "playbook_id": playbook_id,
                    "inventory_id": inventory_id,
                    "credential_id": credential_id,
                },
            )
            assert response.status_code == 201
            queued[inventory_id].append(response.json()["id"])
    return queued


def _claim(worker_id: str = "w"):
    db = get_sessionmaker()()
    try:
        return claim_next(db, worker_id)
    finally:
        db.close()


def _finish(run_id: int, status: str = "success") -> None:
    with get_engine().begin() as conn:
        conn.execute(
            update(Run)
            .where(Run.id == run_id)
            .values(status=status, finished_at=text("now()"), claim_token_hash=None)
        )


def test_concurrent_claims_never_overlap_an_inventory_and_keep_its_order(client) -> None:
    queued = _queue_runs(client, inventories=3, per_inventory=4)
    inventory_of = {run_id: inv for inv, ids in queued.items() for run_id in ids}
    busy: set[int] = set()
    order: dict[int, list[int]] = defaultdict(list)
    claimed: list[int] = []
    problems: list[str] = []
    lock = threading.Lock()

    def claimer(n: int) -> None:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            with lock:
                if len(claimed) == len(inventory_of):
                    return
            claim = _claim(f"w{n}")
            if claim is None:
                time.sleep(0.005)
                continue
            inventory = inventory_of[claim.run_id]
            with lock:
                if inventory in busy:
                    problems.append(f"run {claim.run_id}: inventory {inventory} already busy")
                busy.add(inventory)
                order[inventory].append(claim.run_id)
                claimed.append(claim.run_id)
            time.sleep(0.02)  # "running"
            with lock:
                busy.discard(inventory)
            _finish(claim.run_id)

    threads = [threading.Thread(target=claimer, args=(n,)) for n in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert problems == []
    assert sorted(claimed) == sorted(inventory_of)  # each run claimed exactly once
    assert dict(order) == dict(queued)  # per inventory, in the order queued


def test_a_claim_records_the_worker_and_its_lease(client) -> None:
    [[run_id]] = _queue_runs(client, 1, 1).values()
    claim = _claim("host-a:42")
    assert claim.run_id == run_id
    assert claim.claim_token != claim.job_token
    with get_engine().connect() as conn:
        row = conn.execute(
            text(
                "SELECT status, worker_id, claim_token_hash, "
                "lease_expires_at - claimed_at AS lease, job_token_expires_at - claimed_at "
                "FROM runs WHERE id = :id"
            ),
            {"id": run_id},
        ).one()
    assert row[0] == "running" and row[1] == "host-a:42"
    assert len(row[2]) == 64 and claim.claim_token not in row[2]  # only a hash is stored
    assert row[3].total_seconds() == 60
    assert row[4].total_seconds() == 60
    assert _claim() is None


def test_nothing_is_claimed_while_a_galaxy_install_waits_or_runs(client) -> None:
    _queue_runs(client, 1, 1)
    db = get_sessionmaker()()
    install = GalaxyInstall(status="queued", triggered_by="admin", requirements_snapshot="x")
    db.add(install)
    db.commit()
    assert _claim() is None
    install.status = "running"
    db.commit()
    assert _claim() is None
    install.status = "success"
    db.commit()
    db.close()
    assert _claim() is not None


def test_a_run_whose_group_was_deleted_is_failed_not_run_on_the_whole_inventory(client) -> None:
    _login(client)
    playbook_id = _create_playbook(client, SUCCESS_PLAYBOOK)
    inventory_id, _ = _create_inventory_with_host(client, "/dev/null")
    group = client.post(f"/api/inventories/{inventory_id}/groups", json={"name": "web"}).json()
    credential_id = _create_credential(client)
    body = {
        "playbook_id": playbook_id,
        "inventory_id": inventory_id,
        "credential_id": credential_id,
    }
    doomed = client.post("/api/runs", json={**body, "group_id": group["id"]}).json()["id"]
    fine = client.post("/api/runs", json=body).json()["id"]

    db = get_sessionmaker()()
    db.delete(db.get(InventoryGroup, group["id"]))
    db.commit()
    db.close()

    claim = _claim()
    assert claim.run_id == fine  # the doomed run was failed on the way, not claimed
    run = client.get(f"/api/runs/{doomed}").json()
    assert run["status"] == "failed"
    assert run["status_reason"] == "not run: its inventory group 'web' was deleted"
    assert run["finished_at"] is not None
    with client.websocket_connect(f"/api/runs/{doomed}/ws") as ws:
        assert "its inventory group 'web' was deleted" in ws.receive_text()


def test_a_queued_run_executes_the_playbook_as_it_was_when_triggered(client) -> None:
    [[run_id]] = _queue_runs(client, 1, 1).values()
    playbook_id = client.get("/api/playbooks").json()[0]["id"]
    edited = client.put(
        f"/api/playbooks/{playbook_id}", json={"name": "test.yml", "content": "- hosts: none\n"}
    )
    assert edited.status_code == 200

    internal = internal_client()
    claim = internal.post("/internal/claim", json={"worker_id": "w", "wait_seconds": 0}).json()
    job = internal.post(
        f"/internal/runs/{run_id}/job",
        json={"job_token": claim["job_token"]},
        headers={"X-Claim-Token": claim["claim_token"]},
    ).json()
    assert job["playbook"] == SUCCESS_PLAYBOOK


def test_run_timeouts_and_playbook_size_are_bounded(client, monkeypatch) -> None:
    _login(client)
    playbook_id = _create_playbook(client, SUCCESS_PLAYBOOK)
    inventory_id, _ = _create_inventory_with_host(client, "/dev/null")
    body = {
        "playbook_id": playbook_id,
        "inventory_id": inventory_id,
        "credential_id": _create_credential(client),
    }
    for bad in (0, 24 * 3600 + 1):
        assert client.post("/api/runs", json={**body, "timeout_seconds": bad}).status_code == 422
    run = client.post("/api/runs", json={**body, "timeout_seconds": 24 * 3600}).json()
    assert run["timeout_seconds"] == 24 * 3600
    assert client.post("/api/runs", json=body).json()["timeout_seconds"] == 7200

    monkeypatch.setattr("app.routers.runs.MAX_PLAYBOOK_SNAPSHOT_BYTES", 10)
    too_big = client.post("/api/runs", json=body)
    assert too_big.status_code == 400
    assert "too large" in too_big.json()["detail"]


def _hold_gate(shared: bool):
    """A connection holding the galaxy gate, as a claim (shared) or an install start does."""
    conn = get_engine().connect()
    fn = "pg_advisory_xact_lock_shared" if shared else "pg_advisory_xact_lock"
    conn.execute(text(f"SELECT {fn}(:key)"), {"key": GALAXY_GATE_KEY})
    return conn


def _finishes_within(fn, seconds: float) -> tuple[bool, list]:
    result: list = []
    thread = threading.Thread(target=lambda: result.append(fn()), daemon=True)
    thread.start()
    thread.join(seconds)
    return not thread.is_alive(), result


def test_an_install_does_not_start_while_a_claim_is_in_flight(client, monkeypatch) -> None:
    monkeypatch.setattr("app.galaxy.run_install", lambda install_id: None)
    db = get_sessionmaker()()
    db.add(GalaxyInstall(status="queued", triggered_by="admin", requirements_snapshot="x"))
    db.commit()
    db.close()
    claim = _hold_gate(shared=True)
    try:
        done, _ = _finishes_within(try_start_install, 0.5)
        assert not done  # waits for the claim's transaction
    finally:
        claim.rollback()
        claim.close()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        db = get_sessionmaker()()
        status = db.query(GalaxyInstall.status).scalar()
        db.close()
        if status == "running":
            break
        time.sleep(0.05)
    assert status == "running"


def test_a_claim_waits_while_an_install_is_being_started(client) -> None:
    _queue_runs(client, 1, 1)
    starting = _hold_gate(shared=False)
    try:
        done, _ = _finishes_within(_claim, 0.5)
        assert not done
    finally:
        starting.rollback()
        starting.close()
