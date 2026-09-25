import sys

from fastapi.testclient import TestClient

from app import hardening, run_executor
from app.subprocess_env import PASSTHROUGH_ENV, clean_env
from tests.test_runs import (
    _create_credential,
    _create_inventory_with_host,
    _create_playbook,
    _login,
    _wait_for_completion,
)

ENV_DUMP_PLAYBOOK = """\
- hosts: all
  connection: local
  gather_facts: false
  tasks:
    - name: dump the environment the run actually sees
      ansible.builtin.command: env
      register: seen
      changed_when: false
    - name: write it out
      ansible.builtin.copy:
        content: "{{ seen.stdout }}"
        dest: "{{ marker_path }}"
"""


def test_clean_env_only_passes_allowlisted_names(monkeypatch) -> None:
    monkeypatch.setenv("CREDENTIAL_ENCRYPTION_KEY", "k")
    monkeypatch.setenv("SOMETHING_ELSE", "x")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = clean_env({"EXTRA": "1"})
    assert set(env) <= {*PASSTHROUGH_ENV, "EXTRA"}
    assert env["PATH"] == "/usr/bin"
    assert env["EXTRA"] == "1"
    assert "CREDENTIAL_ENCRYPTION_KEY" not in env
    assert "SOMETHING_ELSE" not in env


def test_disable_process_inspection_calls_prctl_on_linux(monkeypatch) -> None:
    calls: list[tuple] = []

    class FakeLibc:
        def prctl(self, *args) -> int:
            calls.append(args)
            return 0

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(hardening.ctypes, "CDLL", lambda *a, **k: FakeLibc())
    assert hardening.disable_process_inspection() is True
    assert calls == [(4, 0, 0, 0, 0)]  # PR_SET_DUMPABLE, 0


def test_disable_process_inspection_reports_failure(monkeypatch) -> None:
    class FailingLibc:
        def prctl(self, *args) -> int:
            return -1

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(hardening.ctypes, "CDLL", lambda *a, **k: FailingLibc())
    assert hardening.disable_process_inspection() is False


def test_disable_process_inspection_is_a_noop_off_linux(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")

    def boom(*a, **k):
        raise AssertionError("must not touch libc off Linux")

    monkeypatch.setattr(hardening.ctypes, "CDLL", boom)
    assert hardening.disable_process_inspection() is False


def test_run_does_not_inherit_app_secrets(client: TestClient, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AUTH_SECRET_KEY", "sentinel-auth-secret-key")
    monkeypatch.setenv("ADMIN_PASSWORD", "sentinel-admin-password")
    monkeypatch.setenv("ANSIDECK_TEST_ARBITRARY_SECRET", "sentinel-arbitrary-secret")
    _login(client)
    marker = tmp_path / "env.txt"
    playbook_id = _create_playbook(client, ENV_DUMP_PLAYBOOK)
    inventory_id, _host_id = _create_inventory_with_host(client, str(marker))
    credential_id = _create_credential(client)

    created = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
        },
    )
    run = _wait_for_completion(client, created.json()["id"])
    assert run["status"] == "success"

    seen = marker.read_text()
    names = {line.split("=", 1)[0] for line in seen.splitlines() if "=" in line}
    for name in (
        "CREDENTIAL_ENCRYPTION_KEY",
        "AUTH_SECRET_KEY",
        "ADMIN_PASSWORD",
        "ANSIDECK_TEST_ARBITRARY_SECRET",
    ):
        assert name not in names
    for value in ("sentinel-auth-secret-key", "sentinel-admin-password", "sentinel-arbitrary"):
        assert value not in seen
    # The allowlist still gets through, and runs still see the shared galaxy paths.
    assert "PATH" in names
    assert "ANSIBLE_COLLECTIONS_PATH" in names


def test_run_fails_when_the_worker_dies_without_a_result(
    client: TestClient, tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(
        run_executor,
        "_WORKER_COMMAND",
        [sys.executable, "-c", "import sys; sys.stdin.read(); sys.exit(3)"],
    )
    _login(client)
    playbook_id = _create_playbook(client, ENV_DUMP_PLAYBOOK)
    inventory_id, _host_id = _create_inventory_with_host(client, str(tmp_path / "env.txt"))
    credential_id = _create_credential(client)

    created = client.post(
        "/api/runs",
        json={
            "playbook_id": playbook_id,
            "inventory_id": inventory_id,
            "credential_id": credential_id,
        },
    )
    run = _wait_for_completion(client, created.json()["id"])
    assert run["status"] == "failed"
    assert run["return_code"] == 3
