import glob
import json
import sys
import tempfile
import textwrap
import time
from datetime import datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

REDACTED_MARKER = "[REDACTED]"

FINISHED = ("success", "failed", "cancelled", "timed_out")

SUCCESS_PLAYBOOK = """\
- hosts: all
  connection: local
  gather_facts: false
  tasks:
    - name: write marker
      ansible.builtin.copy:
        content: "run marker"
        dest: "{{ marker_path }}"
"""

FAILURE_PLAYBOOK = """\
- hosts: all
  connection: local
  gather_facts: false
  tasks:
    - name: fail on purpose
      ansible.builtin.fail:
        msg: "intentional failure"
"""

EXTRA_VARS_PLAYBOOK = """\
- hosts: all
  connection: local
  gather_facts: false
  tasks:
    - name: write extra var
      ansible.builtin.copy:
        content: "{{ greeting }}"
        dest: "{{ marker_path }}"
"""

VAULT_VAR_PLAYBOOK_TEMPLATE = """\
- hosts: all
  connection: local
  gather_facts: false
  vars:
{vault_block}
  tasks:
    - name: write decrypted vault var
      ansible.builtin.copy:
        content: "{{{{ secret_value }}}}"
        dest: "{{{{ marker_path }}}}"
"""

PAUSE_PLAYBOOK = """\
- hosts: all
  connection: local
  gather_facts: false
  tasks:
    - name: pause a moment
      ansible.builtin.pause:
        seconds: 3
"""


def _login(client: TestClient) -> None:
    assert (
        client.post("/api/auth/login", json={"username": "admin", "password": "admin"}).status_code
        == 200
    )


def _generate_key_pem() -> str:
    # Native OpenSSH format, not PKCS8: this key actually gets handed to
    # ssh-add (via ansible-runner) during these tests, and ssh-add rejects
    # PKCS8-encoded ed25519 keys as "invalid format" even though they're
    # perfectly valid PEM — this is the format real ssh-keygen output uses.
    private_key = ed25519.Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode()


def _create_playbook(client: TestClient, content: str, name: str = "test.yml") -> int:
    response = client.post("/api/playbooks", json={"name": name, "content": content})
    assert response.status_code == 201
    return response.json()["id"]


def _create_inventory_with_host(
    client: TestClient, marker_path: str, name: str = "test-inv"
) -> tuple[int, int]:
    inv = client.post("/api/inventories", json={"name": name})
    assert inv.status_code == 201
    inventory_id = inv.json()["id"]

    host = client.post(
        f"/api/inventories/{inventory_id}/hosts",
        json={"hostname": "test-host", "vars": {"marker_path": marker_path}},
    )
    assert host.status_code == 201
    return inventory_id, host.json()["id"]


def _create_inventory_with_two_hosts(
    client: TestClient, marker_path_a: str, marker_path_b: str
) -> tuple[int, str, str]:
    inv = client.post("/api/inventories", json={"name": "test-inv-2host"})
    assert inv.status_code == 201
    inventory_id = inv.json()["id"]

    for hostname, marker_path in (("host-a", marker_path_a), ("host-b", marker_path_b)):
        response = client.post(
            f"/api/inventories/{inventory_id}/hosts",
            json={"hostname": hostname, "vars": {"marker_path": marker_path}},
        )
        assert response.status_code == 201

    return inventory_id, "host-a", "host-b"


def _create_credential(client: TestClient, name: str = "test-cred") -> int:
    response = client.post(
        "/api/credentials", json={"name": name, "private_key": _generate_key_pem()}
    )
    assert response.status_code == 201
    return response.json()["id"]


def _create_vault_password(
    client: TestClient, name: str = "test-vault", password: str = "vault-pass"
) -> int:
    response = client.post("/api/vault-passwords", json={"name": name, "password": password})
    assert response.status_code == 201
    return response.json()["id"]


def _encrypt_with_vault(client: TestClient, vault_password_id: int, plaintext: str) -> dict:
    response = client.post(
        "/api/vault/encrypt",
        json={
            "vault_password_id": vault_password_id,
            "plaintext": plaintext,
            "var_name": "secret_value",
        },
    )
    assert response.status_code == 200
    return response.json()


def _vault_var_playbook(yaml_block: str) -> str:
    return VAULT_VAR_PLAYBOOK_TEMPLATE.format(vault_block=textwrap.indent(yaml_block, "    "))


def _wait_for_completion(client: TestClient, run_id: int, timeout: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in FINISHED:
            return run
        time.sleep(0.2)
    raise AssertionError(f"run {run_id} did not finish within {timeout}s")


def _wait_for_status(client: TestClient, run_id: int, status: str, timeout: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] == status:
            return run
        time.sleep(0.1)
    raise AssertionError(f"run {run_id} never became {status} (now {run['status']})")


def test_runs_require_auth(client: TestClient) -> None:
    assert client.get("/api/runs").status_code == 401
    assert client.get("/api/runs/1").status_code == 401
    assert (
        client.post(
            "/api/runs",
            json={"playbook_id": 1, "inventory_id": 1, "credential_id": 1},
        ).status_code
        == 401
    )


def test_create_run_validates_inputs(client: TestClient, tmp_path) -> None:
    _login(client)
    marker_path = str(tmp_path / "marker.txt")
    playbook_id = _create_playbook(client, SUCCESS_PLAYBOOK)
    inventory_id, _host_id = _create_inventory_with_host(client, marker_path)
    credential_id = _create_credential(client)

    missing_playbook = client.post(
        "/api/runs",
        json={"playbook_id": 999, "inventory_id": inventory_id, "credential_id": credential_id},
    )
    assert missing_playbook.status_code == 404

    missing_inventory = client.post(
        "/api/runs",
        json={"playbook_id": playbook_id, "inventory_id": 999, "credential_id": credential_id},
    )
    assert missing_inventory.status_code == 404

    missing_credential = client.post(
        "/api/runs",
        json={"playbook_id": playbook_id, "inventory_id": inventory_id, "credential_id": 999},
    )
    assert missing_credential.status_code == 404

    other_inv = client.post("/api/inventories", json={"name": "other-inv"})
    other_group = client.post(
        f"/api/inventories/{other_inv.json()['id']}/groups", json={"name": "g"}
    )
    mismatched_group = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "group_id": other_group.json()["id"],
            "credential_id": credential_id,
        },
    )
    assert mismatched_group.status_code == 400


def test_run_success(client: TestClient, tmp_path) -> None:
    _login(client)
    marker_path = str(tmp_path / "marker.txt")
    playbook_id = _create_playbook(client, SUCCESS_PLAYBOOK)
    inventory_id, _host_id = _create_inventory_with_host(client, marker_path)
    credential_id = _create_credential(client)

    create_response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
            "become": False,
        },
    )
    assert create_response.status_code == 201
    run_id = create_response.json()["id"]
    assert create_response.json()["status"] == "queued"
    assert create_response.json()["triggered_by"] == "admin"

    run = _wait_for_completion(client, run_id)
    assert run["status"] == "success"
    assert run["return_code"] == 0
    assert (tmp_path / "marker.txt").read_text() == "run marker"

    assert run["worker_id"] == "test-worker"
    assert run["status_reason"] is None
    assert run["timeout_seconds"] == 7200
    assert run["attempt"] == 1
    lifecycle = [run[k] for k in ("queued_at", "claimed_at", "started_at", "finished_at")]
    assert all(lifecycle)
    assert [datetime.fromisoformat(t) for t in lifecycle] == sorted(
        datetime.fromisoformat(t) for t in lifecycle
    )
    assert _host_counts(run) == {"total": 1, "ok": 1, "changed": 1, "failed": 0, "unreachable": 0}


def test_run_failure(client: TestClient, tmp_path) -> None:
    _login(client)
    marker_path = str(tmp_path / "marker.txt")
    playbook_id = _create_playbook(client, FAILURE_PLAYBOOK, name="fail.yml")
    inventory_id, _host_id = _create_inventory_with_host(client, marker_path)
    credential_id = _create_credential(client)

    create_response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
        },
    )
    run_id = create_response.json()["id"]

    run = _wait_for_completion(client, run_id)
    assert run["status"] == "failed"
    assert run["return_code"] != 0
    assert _host_counts(run) == {"total": 1, "ok": 0, "changed": 0, "failed": 1, "unreachable": 0}


def _host_counts(run: dict) -> dict:
    return {k: run[f"hosts_{k}"] for k in ("total", "ok", "changed", "failed", "unreachable")}


def test_run_counts_unreachable_hosts_separately(client: TestClient) -> None:
    _login(client)
    playbook_id = _create_playbook(
        client, "- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.ping:\n"
    )
    inventory_id = client.post("/api/inventories", json={"name": "mixed"}).json()["id"]
    for hostname, host_vars in (
        ("here", {"ansible_connection": "local", "ansible_python_interpreter": sys.executable}),
        ("nowhere", {"ansible_host": "127.0.0.1", "ansible_port": 1}),  # nothing listens
    ):
        response = client.post(
            f"/api/inventories/{inventory_id}/hosts", json={"hostname": hostname, "vars": host_vars}
        )
        assert response.status_code == 201, response.text
    run_id = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client),
        },
    ).json()["id"]

    run = _wait_for_completion(client, run_id, timeout=60)
    assert run["status"] == "failed"
    assert _host_counts(run) == {"total": 2, "ok": 1, "changed": 0, "failed": 0, "unreachable": 1}


def test_host_counts_read_the_play_recap_and_tolerate_junk() -> None:
    from app.run_executor import host_counts

    recap = {
        "processed": {"a": 1, "b": 1, "c": 1, "d": 1},
        "ok": {"a": 3, "b": 1, "c": 0},
        "changed": {"a": 2, "b": 0},
        "failures": {"b": 1},
        "dark": {"c": 1, "b": 1},
        "skipped": {"d": 2},
    }
    assert host_counts(recap) == {
        "hosts_total": 4,
        "hosts_ok": 2,  # a, and d (only skipped tasks)
        "hosts_changed": 1,
        "hosts_failed": 1,
        "hosts_unreachable": 2,
    }
    nothing = dict.fromkeys(host_counts({}), 0)
    for junk in (None, "x", [], {"failures": "x", "dark": {"h": "1"}, "ok": {"h": None}}):
        assert host_counts(junk) == nothing


def test_run_cleans_up_private_data_dir(client: TestClient, tmp_path) -> None:
    _login(client)
    marker_path = str(tmp_path / "marker.txt")
    playbook_id = _create_playbook(client, SUCCESS_PLAYBOOK)
    inventory_id, _host_id = _create_inventory_with_host(client, marker_path)
    credential_id = _create_credential(client)

    create_response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
        },
    )
    run_id = create_response.json()["id"]
    _wait_for_completion(client, run_id)

    leftover = glob.glob(f"{tempfile.gettempdir()}/ansideck-run-{run_id}-*")
    assert leftover == []


def test_run_never_logs_key_material(client: TestClient, tmp_path) -> None:
    _login(client)
    marker_path = str(tmp_path / "marker.txt")
    playbook_id = _create_playbook(client, SUCCESS_PLAYBOOK)
    inventory_id, _host_id = _create_inventory_with_host(client, marker_path)

    key_pem = _generate_key_pem()
    cred_response = client.post(
        "/api/credentials", json={"name": "sensitive-cred", "private_key": key_pem}
    )
    credential_id = cred_response.json()["id"]

    create_response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
        },
    )
    run_id = create_response.json()["id"]
    _wait_for_completion(client, run_id)

    log_path = tmp_path / "runs" / f"{run_id}.jsonl"
    assert log_path.exists()
    assert key_pem not in log_path.read_text()


def test_run_extra_vars_reach_playbook(client: TestClient, tmp_path) -> None:
    _login(client)
    marker_path = str(tmp_path / "marker.txt")
    playbook_id = _create_playbook(client, EXTRA_VARS_PLAYBOOK, name="extra-vars.yml")
    inventory_id, _host_id = _create_inventory_with_host(client, marker_path)
    credential_id = _create_credential(client)

    create_response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
            "extra_vars": {"greeting": "hello from extra-vars"},
        },
    )
    assert create_response.status_code == 201
    assert create_response.json()["extra_vars"] == {"greeting": "hello from extra-vars"}
    run_id = create_response.json()["id"]

    run = _wait_for_completion(client, run_id)
    assert run["status"] == "success"
    assert (tmp_path / "marker.txt").read_text() == "hello from extra-vars"


def test_run_check_mode_prevents_changes(client: TestClient, tmp_path) -> None:
    _login(client)
    marker_path = str(tmp_path / "marker.txt")
    playbook_id = _create_playbook(client, SUCCESS_PLAYBOOK, name="check-mode.yml")
    inventory_id, _host_id = _create_inventory_with_host(client, marker_path)
    credential_id = _create_credential(client)

    create_response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
            "check_mode": True,
        },
    )
    run_id = create_response.json()["id"]

    run = _wait_for_completion(client, run_id)
    assert run["status"] == "success"
    assert not (tmp_path / "marker.txt").exists()


def test_run_diff_mode_includes_diff_output(client: TestClient, tmp_path) -> None:
    _login(client)
    marker_path = str(tmp_path / "marker.txt")
    playbook_id = _create_playbook(client, SUCCESS_PLAYBOOK, name="diff-mode.yml")
    inventory_id, _host_id = _create_inventory_with_host(client, marker_path)
    credential_id = _create_credential(client)

    create_response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
            "diff_mode": True,
        },
    )
    run_id = create_response.json()["id"]
    _wait_for_completion(client, run_id)

    log_path = tmp_path / "runs" / f"{run_id}.jsonl"
    events = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
    diffs = [e["event_data"].get("diff") for e in events if "diff" in e.get("event_data", {})]
    assert any(diffs), f"expected at least one event with non-empty diff data, got events: {events}"


def test_run_limit_narrows_target(client: TestClient, tmp_path) -> None:
    _login(client)
    marker_a = str(tmp_path / "marker-a.txt")
    marker_b = str(tmp_path / "marker-b.txt")
    playbook_id = _create_playbook(client, SUCCESS_PLAYBOOK, name="limit.yml")
    inventory_id, host_a, _host_b = _create_inventory_with_two_hosts(client, marker_a, marker_b)
    credential_id = _create_credential(client)

    create_response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
            "limit": host_a,
        },
    )
    run_id = create_response.json()["id"]
    run = _wait_for_completion(client, run_id)

    assert run["status"] == "success"
    assert (tmp_path / "marker-a.txt").exists()
    assert not (tmp_path / "marker-b.txt").exists()


def _start_pause_run(client: TestClient, tmp_path, name: str = "pause-ws.yml") -> int:
    playbook_id = _create_playbook(client, PAUSE_PLAYBOOK, name=name)
    inventory_id, _ = _create_inventory_with_host(client, str(tmp_path / "marker.txt"))
    run = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client),
        },
    )
    assert run.status_code == 201
    return run.json()["id"]


def _run_topics() -> set[str]:
    """Topics someone listens on for a run's log (workers' claims listen on "queue")."""
    from app.notify import notifier

    return {topic for topic in notifier.topics() if topic.startswith("run:")}


def _receive_until_closed(ws) -> tuple[list[str], int]:
    lines = []
    with pytest.raises(WebSocketDisconnect) as closed:
        while True:
            lines.append(ws.receive_text())
    return lines, closed.value.code


def test_live_run_websocket_streams_to_the_end_without_holding_a_transaction(
    client: TestClient, tmp_path
) -> None:
    from sqlalchemy import text

    from app.db import get_engine

    # A plain TestClient: the run's thread notifies whichever loop the socket lives on.
    _login(client)
    run_id = _start_pause_run(client, tmp_path)

    with client.websocket_connect(f"/api/runs/{run_id}/ws") as ws:
        first = ws.receive_text()  # streaming live, mid-pause
        with get_engine().connect() as conn:
            idle = conn.execute(
                text(
                    "SELECT query FROM pg_stat_activity WHERE datname = current_database() "
                    "AND state LIKE 'idle in transaction%' AND pid <> pg_backend_pid()"
                )
            ).scalars()
            assert list(idle) == []
        rest, code = _receive_until_closed(ws)

    # Code 1000 means "that was everything": the stream matches the log line for line.
    assert code == 1000
    log = (tmp_path / "runs" / f"{run_id}.jsonl").read_text().splitlines()
    assert [first, *rest] == log
    assert json.loads(log[-1])["event"] == "playbook_on_stats"
    assert _wait_for_completion(client, run_id)["status"] == "success"
    assert _run_topics() == set()


def test_run_websocket_resumes_from_a_line(client: TestClient, tmp_path) -> None:
    _login(client)
    run_id = _start_pause_run(client, tmp_path)
    _wait_for_completion(client, run_id)
    log = (tmp_path / "runs" / f"{run_id}.jsonl").read_text().splitlines()
    assert len(log) > 3

    for start in (0, 2, len(log), len(log) + 5):
        with client.websocket_connect(f"/api/runs/{run_id}/ws?from={start}") as ws:
            assert _receive_until_closed(ws) == (log[start:], 1000)

    with pytest.raises(WebSocketDisconnect) as rejected:
        with client.websocket_connect(f"/api/runs/{run_id}/ws?from=-1"):
            pass
    assert rejected.value.code == 1008


def test_a_viewer_leaving_mid_run_stops_its_stream(client: TestClient, tmp_path) -> None:
    from app.notify import run_topic

    _login(client)
    run_id = _start_pause_run(client, tmp_path)
    with client.websocket_connect(f"/api/runs/{run_id}/ws") as ws:
        assert ws.receive_text()
        assert _run_topics() == {run_topic(run_id)}
        # Leave inside the block: on exit, the TestClient cancels the app outright.
        ws.send({"type": "websocket.disconnect", "code": 1001})
        deadline = time.monotonic() + 1
        while _run_topics() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert _run_topics() == set()
    assert client.get(f"/api/runs/{run_id}").json()["status"] == "running"  # not waited out
    _wait_for_completion(client, run_id)


def test_a_second_run_on_a_busy_inventory_waits_its_turn(client: TestClient, tmp_path) -> None:
    _login(client)
    playbook_id = _create_playbook(client, PAUSE_PLAYBOOK, name="pause.yml")
    inventory_id, _host_id = _create_inventory_with_host(client, str(tmp_path / "marker.txt"))
    payload = {
        "playbook_id": playbook_id,
        "inventory_id": inventory_id,
        "credential_id": _create_credential(client),
    }
    first = client.post("/api/runs", json=payload)
    assert first.status_code == 201
    _wait_for_status(client, first.json()["id"], "running")

    second = client.post("/api/runs", json=payload)
    assert second.status_code == 201  # accepted and queued, no longer refused
    time.sleep(1)  # the worker has free slots, but the inventory is busy
    assert client.get(f"/api/runs/{second.json()['id']}").json()["status"] == "queued"

    first_run = _wait_for_completion(client, first.json()["id"])
    second_run = _wait_for_completion(client, second.json()["id"])
    assert second_run["status"] == "success"
    assert first_run["finished_at"] <= second_run["claimed_at"]


def test_concurrency_guard_allows_run_after_previous_completes(
    client: TestClient, tmp_path
) -> None:
    _login(client)
    marker_path = str(tmp_path / "marker.txt")
    playbook_id = _create_playbook(client, SUCCESS_PLAYBOOK, name="quick.yml")
    inventory_id, _host_id = _create_inventory_with_host(client, marker_path)
    credential_id = _create_credential(client)

    payload = {
        "playbook_id": playbook_id,
        "inventory_id": inventory_id,
        "credential_id": credential_id,
    }
    first = client.post("/api/runs", json=payload)
    _wait_for_completion(client, first.json()["id"])

    second = client.post("/api/runs", json=payload)
    assert second.status_code == 201
    _wait_for_completion(client, second.json()["id"])


def test_concurrency_guard_allows_different_inventories_concurrently(
    client: TestClient, tmp_path
) -> None:
    _login(client)
    marker_a = str(tmp_path / "marker-a.txt")
    marker_b = str(tmp_path / "marker-b.txt")
    playbook_id = _create_playbook(client, PAUSE_PLAYBOOK, name="pause2.yml")
    inventory_a, _ = _create_inventory_with_host(client, marker_a, name="test-inv-a")
    inventory_b, _ = _create_inventory_with_host(client, marker_b, name="test-inv-b")
    credential_id = _create_credential(client)

    first = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_a,
            "credential_id": credential_id,
        },
    )
    second = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_b,
            "credential_id": credential_id,
        },
    )
    assert first.status_code == 201
    assert second.status_code == 201

    _wait_for_completion(client, first.json()["id"])
    _wait_for_completion(client, second.json()["id"])


def test_create_run_rejects_missing_vault_password(client: TestClient, tmp_path) -> None:
    _login(client)
    playbook_id = _create_playbook(client, SUCCESS_PLAYBOOK)
    inventory_id, _host_id = _create_inventory_with_host(client, str(tmp_path / "marker.txt"))
    credential_id = _create_credential(client)

    response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
            "vault_password_id": 999,
        },
    )
    assert response.status_code == 404


def test_run_decrypts_vault_var_in_playbook(client: TestClient, tmp_path) -> None:
    _login(client)
    vault_password_id = _create_vault_password(client)
    encrypted = _encrypt_with_vault(client, vault_password_id, "decrypted-from-playbook")
    playbook_id = _create_playbook(
        client, _vault_var_playbook(encrypted["yaml_block"]), name="vault-playbook.yml"
    )
    inventory_id, _host_id = _create_inventory_with_host(client, str(tmp_path / "marker.txt"))
    credential_id = _create_credential(client)

    create_response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
            "vault_password_id": vault_password_id,
        },
    )
    assert create_response.status_code == 201
    assert create_response.json()["vault_password_name"] == "test-vault"

    run = _wait_for_completion(client, create_response.json()["id"])
    assert run["status"] == "success", run
    assert (tmp_path / "marker.txt").read_text() == "decrypted-from-playbook"


def test_run_decrypts_raw_envelope_in_extra_vars(client: TestClient, tmp_path) -> None:
    _login(client)
    vault_password_id = _create_vault_password(client)
    encrypted = _encrypt_with_vault(client, vault_password_id, "decrypted-from-extra-vars")
    playbook_id = _create_playbook(client, EXTRA_VARS_PLAYBOOK, name="vault-extra-vars.yml")
    inventory_id, _host_id = _create_inventory_with_host(client, str(tmp_path / "marker.txt"))
    credential_id = _create_credential(client)

    create_response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
            "vault_password_id": vault_password_id,
            "extra_vars": {"greeting": encrypted["vault_text"]},
        },
    )
    assert create_response.status_code == 201

    run = _wait_for_completion(client, create_response.json()["id"])
    assert run["status"] == "success", run
    assert (tmp_path / "marker.txt").read_text() == "decrypted-from-extra-vars"


def test_run_needing_vault_without_password_fails_cleanly(client: TestClient, tmp_path) -> None:
    _login(client)
    vault_password_id = _create_vault_password(client)
    encrypted = _encrypt_with_vault(client, vault_password_id, "never-decrypted")
    playbook_id = _create_playbook(
        client, _vault_var_playbook(encrypted["yaml_block"]), name="vault-no-password.yml"
    )
    inventory_id, _host_id = _create_inventory_with_host(client, str(tmp_path / "marker.txt"))
    credential_id = _create_credential(client)

    create_response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
        },
    )
    run = _wait_for_completion(client, create_response.json()["id"])

    assert run["status"] == "failed"
    assert run["return_code"] != 0
    assert not (tmp_path / "marker.txt").exists()


def test_run_with_wrong_vault_password_fails_cleanly(client: TestClient, tmp_path) -> None:
    _login(client)
    right_id = _create_vault_password(client, name="right", password="right-password")
    wrong_id = _create_vault_password(client, name="wrong", password="wrong-password")
    encrypted = _encrypt_with_vault(client, right_id, "never-decrypted")
    playbook_id = _create_playbook(
        client, _vault_var_playbook(encrypted["yaml_block"]), name="vault-wrong-password.yml"
    )
    inventory_id, _host_id = _create_inventory_with_host(client, str(tmp_path / "marker.txt"))
    credential_id = _create_credential(client)

    create_response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
            "vault_password_id": wrong_id,
        },
    )
    run = _wait_for_completion(client, create_response.json()["id"])

    assert run["status"] == "failed"
    assert not (tmp_path / "marker.txt").exists()


def test_run_never_logs_vault_password(client: TestClient, tmp_path) -> None:
    _login(client)
    password = "super-secret-vault-password-9d1f"
    vault_password_id = _create_vault_password(client, password=password)
    encrypted = _encrypt_with_vault(client, vault_password_id, "log-check-plaintext")
    playbook_id = _create_playbook(
        client, _vault_var_playbook(encrypted["yaml_block"]), name="vault-log-check.yml"
    )
    inventory_id, _host_id = _create_inventory_with_host(client, str(tmp_path / "marker.txt"))
    credential_id = _create_credential(client)

    create_response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
            "vault_password_id": vault_password_id,
        },
    )
    run_id = create_response.json()["id"]
    run = _wait_for_completion(client, run_id)
    assert run["status"] == "success", run

    log_path = tmp_path / "runs" / f"{run_id}.jsonl"
    assert log_path.exists()
    assert password not in log_path.read_text()
    assert password not in client.get(f"/api/runs/{run_id}").text


def test_deleting_vault_password_keeps_run_history_name(client: TestClient, tmp_path) -> None:
    _login(client)
    vault_password_id = _create_vault_password(client, name="ephemeral-vault")
    playbook_id = _create_playbook(client, SUCCESS_PLAYBOOK)
    inventory_id, _host_id = _create_inventory_with_host(client, str(tmp_path / "marker.txt"))
    credential_id = _create_credential(client)

    create_response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
            "vault_password_id": vault_password_id,
        },
    )
    run_id = create_response.json()["id"]
    _wait_for_completion(client, run_id)

    assert client.delete(f"/api/vault-passwords/{vault_password_id}").status_code == 204

    run = client.get(f"/api/runs/{run_id}").json()
    assert run["vault_password_name"] == "ephemeral-vault"


SCRUB_PLAYBOOK_TEMPLATE = """\
- hosts: all
  connection: local
  gather_facts: false
  vars:
{vault_block}
  tasks:
    - name: print vault-decrypted var
      ansible.builtin.debug:
        msg: "vault: {{{{ vaulted_secret }}}}"
    - name: print secret extra var
      ansible.builtin.debug:
        msg: "extra: {{{{ db_password }}}}"
    - name: print secret host var
      ansible.builtin.debug:
        msg: "hostvar: {{{{ ansible_password }}}}"
    - name: print short secret
      ansible.builtin.debug:
        msg: "short: {{{{ tiny_secret }}}}"
    - name: print a key block
      ansible.builtin.debug:
        msg: |
          -----BEGIN RSA PRIVATE KEY-----
          MIIEpAIBAAKCAQEAplantedkeymaterial0123456789
          -----END RSA PRIVATE KEY-----
    - name: print credentials from a task
      ansible.builtin.debug:
        msg: "curl -H 'Authorization: Bearer planted.bearer-token_123' https://deploy:planted-url-pw@example.com/x"
    - name: print something harmless
      ansible.builtin.debug:
        msg: "visible: hello world"
    - name: no_log task
      ansible.builtin.debug:
        msg: "nolog: {{{{ db_password }}}}"
      no_log: true
"""

SCRUB_PLANTED = {
    "vault": "planted-vault-plaintext-111",
    "extra": "planted-extra-var-222",
    "hostvar": "planted-host-var-333",
    "key": "MIIEpAIBAAKCAQEAplantedkeymaterial0123456789",
    "bearer": "planted.bearer-token_123",
    "urlpw": "planted-url-pw",
}


def _scrub_run(client: TestClient, tmp_path) -> tuple[int, str]:
    vault_password_id = _create_vault_password(client)
    encrypted = client.post(
        "/api/vault/encrypt",
        json={
            "vault_password_id": vault_password_id,
            "plaintext": SCRUB_PLANTED["vault"],
            "var_name": "vaulted_secret",
        },
    ).json()
    playbook_id = _create_playbook(
        client,
        SCRUB_PLAYBOOK_TEMPLATE.format(
            vault_block=textwrap.indent(encrypted["yaml_block"], "    ")
        ),
        name="scrub.yml",
    )
    inv = client.post("/api/inventories", json={"name": "scrub-inv"}).json()
    client.post(
        f"/api/inventories/{inv['id']}/hosts",
        json={"hostname": "scrub-host", "vars": {"ansible_password": SCRUB_PLANTED["hostvar"]}},
    )
    credential_id = _create_credential(client)

    response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inv["id"],
            "credential_id": credential_id,
            "vault_password_id": vault_password_id,
            "extra_vars": {"db_password": SCRUB_PLANTED["extra"], "tiny_secret": "abc"},
        },
    )
    assert response.status_code == 201
    run_id = response.json()["id"]
    run = _wait_for_completion(client, run_id)
    assert run["status"] == "success", run
    return run_id, response.text


def test_run_output_is_scrubbed_in_log_stream_and_replay(client: TestClient, tmp_path) -> None:
    _login(client)
    run_id, create_body = _scrub_run(client, tmp_path)

    log_text = (tmp_path / "runs" / f"{run_id}.jsonl").read_text()
    with client.websocket_connect(f"/api/runs/{run_id}/ws") as ws:
        replay_text = ""
        try:
            while True:
                replay_text += ws.receive_text()
        except Exception:  # noqa: BLE001 - server closes the socket when replay ends
            pass
    api_text = client.get(f"/api/runs/{run_id}").text + client.get("/api/runs").text

    for name, text in {
        "jsonl": log_text,
        "replay": replay_text,
        "api": api_text,
        "create-response": create_body,
    }.items():
        for label, secret in SCRUB_PLANTED.items():
            assert secret not in text, f"{label} secret leaked into {name}"

    assert replay_text, "expected the replay to contain events"
    assert REDACTED_MARKER in log_text
    assert "visible: hello world" in log_text

    events = [json.loads(line) for line in log_text.splitlines() if line.strip()]
    assert all("event" in e for e in events)
    assert {"playbook_on_start", "runner_on_ok", "playbook_on_stats"} <= {
        e["event"] for e in events
    }


def test_run_output_no_log_task_stays_censored(client: TestClient, tmp_path) -> None:
    _login(client)
    run_id, _ = _scrub_run(client, tmp_path)
    log_text = (tmp_path / "runs" / f"{run_id}.jsonl").read_text()
    assert "no_log: true" in log_text


def test_short_secret_does_not_shred_run_output(client: TestClient, tmp_path) -> None:
    _login(client)
    run_id, _ = _scrub_run(client, tmp_path)
    log_text = (tmp_path / "runs" / f"{run_id}.jsonl").read_text()
    # "abc" is below the redaction threshold: it stays visible rather than
    # shredding every occurrence in the log (documented limitation).
    assert "short: abc" in log_text


def test_run_response_masks_secret_looking_extra_vars(client: TestClient, tmp_path) -> None:
    _login(client)
    playbook_id = _create_playbook(client, EXTRA_VARS_PLAYBOOK, name="mask.yml")
    inventory_id, _host_id = _create_inventory_with_host(client, str(tmp_path / "marker.txt"))
    credential_id = _create_credential(client)

    response = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
            "extra_vars": {"greeting": "hello mask", "db_password": "masked-me-please"},
        },
    )
    assert response.status_code == 201
    run_id = response.json()["id"]
    assert response.json()["extra_vars"] == {"greeting": "hello mask", "db_password": "[REDACTED]"}
    _wait_for_completion(client, run_id)

    for text in (client.get(f"/api/runs/{run_id}").text, client.get("/api/runs").text):
        assert "masked-me-please" not in text
        assert "hello mask" in text
