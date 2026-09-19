import glob
import json
import tempfile
import textwrap
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


def _create_credential(client: TestClient) -> int:
    response = client.post(
        "/api/credentials", json={"name": "test-cred", "private_key": _generate_key_pem()}
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


def test_concurrency_guard_blocks_second_run_same_inventory(client: TestClient, tmp_path) -> None:
    _login(client)
    marker_path = str(tmp_path / "marker.txt")
    playbook_id = _create_playbook(client, PAUSE_PLAYBOOK, name="pause.yml")
    inventory_id, _host_id = _create_inventory_with_host(client, marker_path)
    credential_id = _create_credential(client)

    payload = {
        "playbook_id": playbook_id,
        "inventory_id": inventory_id,
        "credential_id": credential_id,
    }
    first = client.post("/api/runs", json=payload)
    assert first.status_code == 201
    first_id = first.json()["id"]
    assert first.json()["status"] == "queued"

    second = client.post("/api/runs", json=payload)
    assert second.status_code == 409
    assert str(first_id) in second.json()["detail"]

    _wait_for_completion(client, first_id)


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
