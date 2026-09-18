import glob
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

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


def _create_inventory_with_host(client: TestClient, marker_path: str) -> tuple[int, int]:
    inv = client.post("/api/inventories", json={"name": "test-inv"})
    assert inv.status_code == 201
    inventory_id = inv.json()["id"]

    host = client.post(
        f"/api/inventories/{inventory_id}/hosts",
        json={"hostname": "test-host", "vars": {"marker_path": marker_path}},
    )
    assert host.status_code == 201
    return inventory_id, host.json()["id"]


def _create_credential(client: TestClient) -> int:
    response = client.post(
        "/api/credentials", json={"name": "test-cred", "private_key": _generate_key_pem()}
    )
    assert response.status_code == 201
    return response.json()["id"]


def _wait_for_completion(client: TestClient, run_id: int, timeout: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in ("success", "failed"):
            return run
        time.sleep(0.2)
    raise AssertionError(f"run {run_id} did not finish within {timeout}s")


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
