import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text, update

from app.db import get_engine, get_sessionmaker
from app.internal_api import MAX_BODY_BYTES, internal_app
from app.main import app
from app.models import AuditEvent, Credential, Run
from tests.conftest import internal_client
from tests.test_runs import (
    SUCCESS_PLAYBOOK,
    _create_credential,
    _create_inventory_with_host,
    _create_playbook,
    _login,
)

pytestmark = pytest.mark.no_worker  # these tests play the worker themselves

INTERNAL_ROUTES = [
    "/internal/ping",
    "/internal/claim",
    "/internal/heartbeat",
    "/internal/runs/1/job",
    "/internal/runs/1/events",
    "/internal/runs/1/complete",
]


def _queue_run(client: TestClient) -> int:
    _login(client)
    response = client.post(
        "/api/runs",
        json={
            "playbook_id": _create_playbook(client, SUCCESS_PLAYBOOK),
            "inventory_id": _create_inventory_with_host(client, "/dev/null")[0],
            "credential_id": _create_credential(client),
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


class Claimed:
    """A run claimed through the internal API, and calls on it as that claim."""

    def __init__(self, client: TestClient) -> None:
        self.run_id = _queue_run(client)
        self.http = internal_client()
        claim = self.http.post("/internal/claim", json={"worker_id": "w", "wait_seconds": 0})
        assert claim.status_code == 200
        body = claim.json()
        assert body["run_id"] == self.run_id
        self.claim_token, self.job_token = body["claim_token"], body["job_token"]

    def post(self, action: str, body: dict, claim_token: str | None = None):
        return self.http.post(
            f"/internal/runs/{self.run_id}/{action}",
            json=body,
            headers={"X-Claim-Token": claim_token or self.claim_token},
        )

    def job(self):
        return self.post("job", {"job_token": self.job_token})

    def events(self, first_seq: int, count: int):
        events = [{"event": "e", "counter": first_seq + n} for n in range(count)]
        return self.post("events", {"first_seq": first_seq, "events": events})

    def complete(self, last_seq: int, status: str = "success"):
        return self.post("complete", {"last_seq": last_seq, "status": status, "return_code": 0})

    def row(self) -> Run:
        db = get_sessionmaker()()
        try:
            return db.get(Run, self.run_id)
        finally:
            db.close()


def _log_counters(tmp_path, run_id: int) -> list[int]:
    lines = (tmp_path / "runs" / f"{run_id}.jsonl").read_text().splitlines()
    return [json.loads(line)["counter"] for line in lines]


def test_every_internal_route_needs_the_worker_token(client) -> None:
    for token in (None, "wrong-token"):
        http = TestClient(internal_app, raise_server_exceptions=False)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        for route in INTERNAL_ROUTES:
            assert http.post(route, json={}, headers=headers).status_code == 401, route
    assert internal_client().post("/internal/ping", json={}).json() == {"ok": True}

    db = get_sessionmaker()()
    failures = db.query(AuditEvent).filter(AuditEvent.action == "worker.auth_failed").count()
    db.close()
    assert failures == 2 * len(INTERNAL_ROUTES)


def test_bad_worker_tokens_are_throttled_per_ip(client) -> None:
    http = TestClient(internal_app, headers={"Authorization": "Bearer nope"})
    codes = [http.post("/internal/ping", json={}).status_code for _ in range(21)]
    assert codes == [401] * 20 + [429]
    # The same address is refused even with the right token until the window passes.
    assert internal_client().post("/internal/ping", json={}).status_code == 429


def test_the_public_app_has_no_internal_routes(client) -> None:
    public = TestClient(app)
    for route in INTERNAL_ROUTES:
        assert public.post(route, json={}).status_code == 404, route


def test_oversized_bodies_are_refused(client) -> None:
    http = internal_client()
    body = b"x" * (MAX_BODY_BYTES + 1)
    response = http.post(
        "/internal/ping", content=body, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413


def test_claim_returns_204_when_there_is_nothing_to_run(client) -> None:
    response = internal_client().post("/internal/claim", json={"worker_id": "w", "wait_seconds": 0})
    assert response.status_code == 204


def test_the_job_is_handed_out_once_and_only_to_the_claim(client) -> None:
    claimed = Claimed(client)
    assert claimed.post("job", {"job_token": claimed.job_token}, "stale").status_code == 410
    assert claimed.post("job", {"job_token": "guess"}).status_code == 410

    job = claimed.job()
    assert job.status_code == 200
    body = job.json()
    assert body["playbook"] == SUCCESS_PLAYBOOK
    assert "BEGIN OPENSSH PRIVATE KEY" in body["ssh_key"]
    assert body["ssh_key"].strip() in body["secrets"]
    assert body["timeout_seconds"] == 7200
    assert claimed.row().started_at is not None
    assert claimed.job().status_code == 410  # single use


def test_an_expired_job_token_is_refused(client) -> None:
    claimed = Claimed(client)
    with get_engine().begin() as conn:
        conn.execute(
            update(Run)
            .where(Run.id == claimed.run_id)
            .values(job_token_expires_at=text("now() - interval '1 second'"))
        )
    assert claimed.job().status_code == 410


def test_a_run_cancelled_before_its_job_was_fetched_never_starts(client) -> None:
    claimed = Claimed(client)
    with get_engine().begin() as conn:
        conn.execute(
            update(Run).where(Run.id == claimed.run_id).values(cancel_requested_at=text("now()"))
        )
    assert claimed.job().status_code == 410
    row = claimed.row()
    assert (row.status, row.status_reason) == ("cancelled", "cancelled before it started")


def test_a_job_that_cannot_be_built_fails_the_run_without_details(client) -> None:
    claimed = Claimed(client)
    db = get_sessionmaker()()
    db.query(Credential).update({Credential.encrypted_private_key: b"not-a-fernet-token"})
    db.commit()
    db.close()
    assert claimed.job().status_code == 410
    row = claimed.row()
    assert row.status == "failed"
    assert row.status_reason == "could not prepare the job (see the server log)"
    assert row.claim_token_hash is None


def test_events_are_appended_once_in_order(client, tmp_path) -> None:
    claimed = Claimed(client)
    assert claimed.events(1, 3).json() == {"acked_seq": 3, "cancel": False}
    # A retry that overlaps what the API already has only adds what's new.
    assert claimed.events(2, 3).json() == {"acked_seq": 4, "cancel": False}
    assert claimed.events(1, 2).json() == {"acked_seq": 4, "cancel": False}
    # A gap is refused, with where to resend from.
    gap = claimed.events(7, 1)
    assert (gap.status_code, gap.json()) == (409, {"expected_seq": 5})
    assert _log_counters(tmp_path, claimed.run_id) == [1, 2, 3, 4]
    assert claimed.row().log_seq == 4


def test_leftovers_of_an_uncommitted_write_are_cut_off(client, tmp_path) -> None:
    claimed = Claimed(client)
    claimed.events(1, 2)
    log = tmp_path / "runs" / f"{claimed.run_id}.jsonl"
    with log.open("a") as f:
        f.write('{"event": "half-written')  # e.g. the API died before committing
    claimed.events(3, 1)
    assert _log_counters(tmp_path, claimed.run_id) == [1, 2, 3]
    assert claimed.row().log_bytes == log.stat().st_size


def test_the_api_scrubs_patterns_as_a_second_layer(client, tmp_path) -> None:
    claimed = Claimed(client)
    leaked = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
    claimed.post("events", {"first_seq": 1, "events": [{"stdout": f"key: {leaked}"}]})
    assert "abc" not in (tmp_path / "runs" / f"{claimed.run_id}.jsonl").read_text()


def test_the_event_ack_carries_a_cancel_request(client) -> None:
    claimed = Claimed(client)
    with get_engine().begin() as conn:
        conn.execute(
            update(Run).where(Run.id == claimed.run_id).values(cancel_requested_at=text("now()"))
        )
    assert claimed.events(1, 1).json() == {"acked_seq": 1, "cancel": True}


def test_complete_waits_for_the_whole_log_then_ends_the_claim(client) -> None:
    claimed = Claimed(client)
    claimed.events(1, 2)
    early = claimed.complete(last_seq=3)
    assert (early.status_code, early.json()) == (409, {"expected_seq": 3})
    assert claimed.row().status == "running"

    done = claimed.post(
        "complete",
        {
            "last_seq": 2,
            "status": "success",
            "return_code": 0,
            "host_counts": {"hosts_total": 2, "hosts_ok": 2, "bogus": 9},
        },
    )
    assert done.status_code == 200
    row = claimed.row()
    assert (row.status, row.return_code, row.hosts_total, row.hosts_ok) == ("success", 0, 2, 2)
    assert row.finished_at is not None
    assert row.claim_token_hash is None and row.lease_expires_at is None
    # The claim is over: nothing more can be written to the run.
    assert claimed.events(3, 1).status_code == 410
    assert claimed.complete(last_seq=2, status="failed").status_code == 410


def test_a_timed_out_run_is_audited(client) -> None:
    claimed = Claimed(client)
    assert claimed.complete(last_seq=0, status="timed_out").status_code == 200
    db = get_sessionmaker()()
    event = db.query(AuditEvent).filter(AuditEvent.action == "run.timed_out").one()
    db.close()
    assert (event.target_id, event.actor_username) == (claimed.run_id, "w")


def test_heartbeats_renew_leases_and_report_cancel_and_gone(client) -> None:
    claimed = Claimed(client)
    with get_engine().begin() as conn:
        conn.execute(
            update(Run)
            .where(Run.id == claimed.run_id)
            .values(lease_expires_at=text("now() + interval '5 seconds'"))
        )

    def beat(token: str) -> str:
        response = claimed.http.post(
            "/internal/heartbeat",
            json={"worker_id": "w", "runs": [{"run_id": claimed.run_id, "claim_token": token}]},
        )
        [answer] = response.json()["runs"]
        return answer["state"]

    assert beat(claimed.claim_token) == "ok"
    row = claimed.row()
    assert (row.lease_expires_at - row.heartbeat_at).total_seconds() == 60
    assert beat("someone-else") == "gone"
    with get_engine().begin() as conn:
        conn.execute(
            update(Run).where(Run.id == claimed.run_id).values(cancel_requested_at=text("now()"))
        )
    assert beat(claimed.claim_token) == "cancel"
    claimed.complete(last_seq=0, status="cancelled")
    assert beat(claimed.claim_token) == "gone"
