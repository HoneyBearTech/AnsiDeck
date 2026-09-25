import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from sqlalchemy import text, update

from app.config import DEFAULT_WORKER_TOKEN, MIN_WORKER_TOKEN_LENGTH
from app.db import get_engine, get_sessionmaker
from app.internal_api import internal_app
from app.models import AuditEvent, Run
from app.reaper import reap_once
from app.run_executor import kill_leftovers
from app.worker import settings as worker_settings
from app.worker.__main__ import FORBIDDEN_ENV, load_settings
from app.worker.client import ApiClient, ApiUnavailable
from app.worker.runner import MAX_EVENT_BYTES, _bounded
from tests.conftest import start_worker
from tests.test_runs import (
    PAUSE_PLAYBOOK,
    SUCCESS_PLAYBOOK,
    _create_credential,
    _create_inventory_with_host,
    _create_playbook,
    _login,
    _wait_for_completion,
    _wait_for_status,
)

BACKEND = Path(__file__).resolve().parents[1]


def _trigger(client, tmp_path, playbook: str = PAUSE_PLAYBOOK, **extra) -> int:
    _login(client)
    response = client.post(
        "/api/runs",
        json={
            "playbook_id": _create_playbook(client, playbook),
            "inventory_id": _create_inventory_with_host(client, str(tmp_path / "m.txt"))[0],
            "credential_id": _create_credential(client),
            **extra,
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def _set(run_id: int, **values) -> None:
    with get_engine().begin() as conn:
        conn.execute(update(Run).where(Run.id == run_id).values(**values))


def _log(tmp_path, run_id: int) -> list[dict]:
    path = tmp_path / "runs" / f"{run_id}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()]


# ------------------------------------------------------------------ in-process worker


def test_a_run_past_its_timeout_is_stopped(client, tmp_path) -> None:
    run_id = _trigger(client, tmp_path, timeout_seconds=1)
    run = _wait_for_completion(client, run_id)
    assert (run["status"], run["status_reason"]) == ("timed_out", "timed out after 1 s")
    assert run["return_code"] is not None
    assert not (tmp_path / "m.txt").exists()


def test_a_running_run_is_cancelled(client, tmp_path) -> None:
    run_id = _trigger(client, tmp_path)
    _wait_for_status(client, run_id, "running")
    _set(run_id, cancel_requested_at=text("now()"), cancel_requested_by="alice")
    started = time.monotonic()
    run = _wait_for_completion(client, run_id)
    assert (run["status"], run["status_reason"]) == ("cancelled", "cancelled by alice")
    assert time.monotonic() - started < 2.5  # well before the 3 s pause would have ended


def test_stopping_the_worker_fails_its_runs(client, tmp_path) -> None:
    run_id = _trigger(client, tmp_path)
    _wait_for_status(client, run_id, "running")
    client.worker.stop()
    run = client.get(f"/api/runs/{run_id}").json()
    assert (run["status"], run["status_reason"]) == ("failed", "stopped: the worker shut down")


def test_a_reaped_run_is_stopped_and_not_overwritten(client, tmp_path) -> None:
    run_id = _trigger(client, tmp_path)
    _wait_for_status(client, run_id, "running")
    _set(run_id, lease_expires_at=text("now() - interval '1 second'"))
    assert reap_once() == [run_id]
    deadline = time.monotonic() + 3
    while client.worker.active_run_ids() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert client.worker.active_run_ids() == []  # heard "gone" and stopped ansible
    run = client.get(f"/api/runs/{run_id}").json()
    assert run["status"] == "failed" and run["status_reason"].startswith("worker lost")


class _NoHeartbeats(ApiClient):
    def post(self, path, body, **kwargs):
        if path == "/internal/heartbeat":
            raise ApiUnavailable("simulated network trouble")
        return super().post(path, body, **kwargs)


@pytest.mark.no_worker
def test_a_worker_that_cannot_renew_its_lease_stops_the_run(client, tmp_path) -> None:
    worker = start_worker(tmp_path / "galaxy", fence_seconds=1)
    worker.client = _NoHeartbeats(worker.client.http)
    try:
        run_id = _trigger(client, tmp_path)
        run = _wait_for_completion(client, run_id)
    finally:
        worker.stop()
    assert run["status"] == "failed"
    assert run["status_reason"] == "stopped: the worker could not reach the API to renew its lease"


def test_every_event_reaches_the_log_in_order(client, tmp_path) -> None:
    run_id = _trigger(client, tmp_path, playbook=SUCCESS_PLAYBOOK)
    assert _wait_for_completion(client, run_id)["status"] == "success"
    events = _log(tmp_path, run_id)
    assert [e["counter"] for e in events] == list(range(1, len(events) + 1))
    assert events[-1]["event"] == "playbook_on_stats"


def test_an_oversized_event_is_truncated_not_lost() -> None:
    event = {"event": "runner_on_ok", "uuid": "u", "counter": 7, "stdout": "x" * MAX_EVENT_BYTES}
    small = _bounded(event)
    assert (small["event"], small["uuid"], small["counter"]) == ("runner_on_ok", "u", 7)
    assert len(json.dumps(small)) < 70_000
    assert small["stdout"].endswith("exceeded 1048576 bytes]")
    assert _bounded({"stdout": "fine"}) == {"stdout": "fine"}


# ------------------------------------------------------------------ worker process


def test_the_worker_imports_nothing_that_could_reach_the_database_or_the_key() -> None:
    code = (
        "import sys, app.worker.__main__; "
        "print('\\n'.join(sorted(m for m in sys.modules if m.split('.')[0] in "
        "('app', 'sqlalchemy', 'psycopg', 'fastapi', 'cryptography'))))"
    )
    loaded = subprocess.run(
        [sys.executable, "-c", code],
        cwd=BACKEND,
        env={"PATH": os.environ["PATH"]},
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    allowed = {
        "app",
        "app.process_hardening",
        "app.run_executor",
        "app.scrub",
        "app.subprocess_env",
        "app.vault",
    }
    unexpected = [m for m in loaded if m not in allowed and not m.startswith("app.worker")]
    # cryptography comes in through ansible's vault support, never app.crypto.
    assert [m for m in unexpected if not m.startswith("cryptography")] == []


def test_the_worker_token_is_removed_from_the_environment(monkeypatch) -> None:
    for name in FORBIDDEN_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("WORKER_TOKEN", "t" * 40)
    assert load_settings().worker_token == "t" * 40
    assert "WORKER_TOKEN" not in os.environ


def test_worker_and_api_agree_on_the_default_token() -> None:
    assert worker_settings.DEFAULT_WORKER_TOKEN == DEFAULT_WORKER_TOKEN
    assert worker_settings.MIN_WORKER_TOKEN_LENGTH == MIN_WORKER_TOKEN_LENGTH


def _worker_env(tmp_path, api_url: str = "http://127.0.0.1:9", **extra: str) -> dict[str, str]:
    return {
        "PATH": os.environ["PATH"],
        "HOME": os.environ.get("HOME", str(tmp_path)),
        "TMPDIR": str(tmp_path),  # its runs' private data dirs land in the test's tmp dir
        "ANSIDECK_API_URL": api_url,
        "GALAXY_DIR": str(tmp_path / "galaxy"),
        "WORKER_ID": "process-worker",
        **extra,
    }


def _start_worker_process(env: dict[str, str]) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "app.worker"],
        cwd=BACKEND,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ({"CREDENTIAL_ENCRYPTION_KEY": "k"}, "CREDENTIAL_ENCRYPTION_KEY must not be set"),
        ({"DATABASE_URL": "postgresql://x"}, "DATABASE_URL must not be set"),
        ({"AUTH_SECRET_KEY": "k"}, "AUTH_SECRET_KEY must not be set"),
        ({"ENVIRONMENT": "production"}, "WORKER_TOKEN still has its insecure default"),
        ({"ENVIRONMENT": "production", "WORKER_TOKEN": "short"}, "at least 32 characters"),
    ],
)
def test_the_worker_refuses_to_start_when_misconfigured(tmp_path, extra, message) -> None:
    proc = _start_worker_process(_worker_env(tmp_path, **extra))
    output, _ = proc.communicate(timeout=30)
    assert proc.returncode != 0
    assert message in output


@pytest.fixture
def internal_api_url(client):
    """The internal API on a real port, for worker processes."""
    server = uvicorn.Server(
        uvicorn.Config(internal_app, host="127.0.0.1", port=0, lifespan="off", log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(10)


def test_a_worker_with_the_wrong_token_refuses_to_start(tmp_path, internal_api_url) -> None:
    env = _worker_env(tmp_path, internal_api_url, WORKER_TOKEN="w" * 40)
    proc = _start_worker_process(env)
    output, _ = proc.communicate(timeout=30)
    assert proc.returncode != 0
    assert "The API refused WORKER_TOKEN" in output


@pytest.mark.no_worker
def test_a_worker_process_finishes_its_run_when_asked_to_stop(
    client, tmp_path, internal_api_url
) -> None:
    proc = _start_worker_process(_worker_env(tmp_path, internal_api_url))
    try:
        run_id = _trigger(client, tmp_path)
        run = _wait_for_status(client, run_id, "running")
        assert run["worker_id"] == "process-worker"
        proc.send_signal(signal.SIGTERM)  # drains: the run may finish (3 s pause)
        output, _ = proc.communicate(timeout=30)
    finally:
        proc.kill()
    assert proc.returncode == 0, output
    run = client.get(f"/api/runs/{run_id}").json()
    assert run["status"] == "success", output
    assert "stopped" in output


@pytest.mark.no_worker
def test_a_killed_worker_process_is_reaped_as_lost(client, tmp_path, internal_api_url) -> None:
    proc = _start_worker_process(_worker_env(tmp_path, internal_api_url))
    try:
        run_id = _trigger(client, tmp_path)
        _wait_for_output(tmp_path, run_id)  # ansible is running, not just the claim
        proc.kill()  # SIGKILL: no drain, no report
        proc.wait(10)
    finally:
        proc.kill()
    assert client.get(f"/api/runs/{run_id}").json()["status"] == "running"
    _set(run_id, lease_expires_at=text("now() - interval '1 second'"))  # skip the 60 s wait
    assert reap_once() == [run_id]
    run = client.get(f"/api/runs/{run_id}").json()
    assert run["status"] == "failed"
    assert run["status_reason"].startswith("worker lost: no heartbeat from process-worker")
    db = get_sessionmaker()()
    assert db.query(AuditEvent).filter(AuditEvent.action == "run.worker_lost").count() == 1
    db.close()
    # A dead worker's ansible lives on outside a container (in one, the kernel ends the whole
    # PID namespace with its PID 1); clean up the way the worker itself would have.
    marker = str(tmp_path / f"ansideck-run-{run_id}-")
    kill_leftovers(marker)
    assert _gone(marker)


def _wait_for_output(tmp_path, run_id: int, timeout: float = 15.0) -> None:
    log = tmp_path / "runs" / f"{run_id}.jsonl"
    deadline = time.monotonic() + timeout
    while not (log.exists() and log.stat().st_size):
        assert time.monotonic() < deadline, "no output from the run"
        time.sleep(0.1)


def _processes_mentioning(fragment: str) -> list[str]:
    out = subprocess.run(["ps", "-axwwo", "pid=,command="], capture_output=True, text=True).stdout
    return [line for line in out.splitlines() if fragment in line]


def _gone(fragment: str, timeout: float = 5.0) -> bool:
    """Killed processes take a moment to be reaped and leave the process table."""
    deadline = time.monotonic() + timeout
    while _processes_mentioning(fragment):
        if time.monotonic() > deadline:
            return False
        time.sleep(0.1)
    return True


def test_nothing_of_a_stopped_run_outlives_it(client, tmp_path) -> None:
    """ansible's task workers leave ansible-playbook's session, so a cancel that only kills
    its process group would leave them running (and hung)."""
    run_id = _trigger(client, tmp_path, timeout_seconds=1)
    assert _wait_for_completion(client, run_id)["status"] == "timed_out"
    assert _gone(f"ansideck-run-{run_id}-")
