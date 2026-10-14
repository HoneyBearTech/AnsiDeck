"""Environment-variable credentials for playbook runs (cloud modules): who may attach which,
what a queued run does when one is deleted, templates, and a real run that sees the variables
in its environment while its output never shows their values."""

import pytest
from fastapi.testclient import TestClient

from tests.conftest import internal_client
from tests.test_projects import _project
from tests.test_runs import (
    SUCCESS_PLAYBOOK,
    _create_credential,
    _create_inventory_with_host,
    _create_playbook,
    _login,
    _wait_for_completion,
)

SECRET = "wJalrXUtnFEMI-K7MDENG-bPxRfiCY"
KEYS = {"AWS_ACCESS_KEY_ID": "AKIAEXAMPLE12345", "AWS_SECRET_ACCESS_KEY": SECRET}


def _env(client: TestClient, name: str, env: dict, **body) -> int:
    response = client.post(
        "/api/credentials", json={"name": name, "kind": "env", "env": env, **body}
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _request(client: TestClient, inventory_id: int, playbook: str = SUCCESS_PLAYBOOK, **body):
    return {
        "playbook_id": _create_playbook(client, playbook, name=body.pop("playbook_name", "p.yml")),
        "inventory_id": inventory_id,
        "credential_id": _create_credential(client, name=body.pop("credential_name", "ssh")),
        **body,
    }


@pytest.mark.no_worker
def test_runs_take_environment_credentials_of_their_project_only(client, tmp_path) -> None:
    _login(client)
    inventory_id, _ = _create_inventory_with_host(client, str(tmp_path / "m"))
    aws = _env(client, "aws", KEYS)
    run = client.post(
        "/api/runs", json=_request(client, inventory_id, env_credential_ids=[aws, aws])
    )
    assert run.status_code == 201, run.text
    assert (run.json()["env_credential_ids"], run.json()["env_credential_names"]) == (
        [aws],
        ["aws"],
    )

    ssh = client.post(
        "/api/runs",
        json=_request(
            client, inventory_id, playbook_name="q.yml", credential_name="ssh2",
            env_credential_ids=[_create_credential(client, name="an-ssh-key")],
        ),
    )  # fmt: skip
    assert ssh.status_code == 400 and "not an environment-variable credential" in ssh.text

    clash = _env(client, "aws-other", {"AWS_SECRET_ACCESS_KEY": "x" * 20})
    both = client.post(
        "/api/runs",
        json=_request(
            client, inventory_id, playbook_name="r.yml", credential_name="ssh3",
            env_credential_ids=[aws, clash],
        ),
    )  # fmt: skip
    assert both.status_code == 400 and "both set AWS_SECRET_ACCESS_KEY" in both.text

    # Made before a second project exists (then every create needs a project_id).
    body = _request(client, inventory_id, playbook_name="s.yml", credential_name="ssh4")
    other = _project(client, "Other")
    foreign = _env(client, "foreign", {"TOKEN": "y" * 20}, project_id=other)
    elsewhere = client.post("/api/runs", json={**body, "env_credential_ids": [foreign]})
    assert elsewhere.status_code == 400 and "same project" in elsewhere.text

    for name in ("SSH_ASKPASS", "SUDO_ASKPASS", "ANSIBLE_HOST_KEY_CHECKING"):
        refused = client.post(
            "/api/credentials",
            json={"name": f"n-{name}", "kind": "env", "env": {name: "x"}, "project_id": 1},
        )
        assert refused.status_code in (400, 422) and "can't be set" in refused.text


@pytest.mark.no_worker
def test_a_queued_run_whose_credential_was_deleted_fails_with_the_reason(client, tmp_path):
    _login(client)
    inventory_id, _ = _create_inventory_with_host(client, str(tmp_path / "m"))
    aws = _env(client, "aws", KEYS)
    run = client.post("/api/runs", json=_request(client, inventory_id, env_credential_ids=[aws]))
    assert client.delete(f"/api/credentials/{aws}").status_code == 204
    http = internal_client()
    claim = http.post(
        "/internal/claim", json={"worker_id": "w", "wait_seconds": 0, "host_keys": True}
    ).json()
    job = http.post(
        f"/internal/runs/{claim['run_id']}/job",
        json={"job_token": claim["job_token"]},
        headers={"X-Claim-Token": claim["claim_token"]},
    )
    assert job.status_code == 410
    failed = client.get(f"/api/runs/{run.json()['id']}").json()
    assert failed["status"] == "failed"
    assert failed["status_reason"] == "not run: its credential 'aws' was deleted"


@pytest.mark.no_worker
def test_templates_keep_their_environment_credentials(client, tmp_path) -> None:
    _login(client)
    inventory_id, _ = _create_inventory_with_host(client, str(tmp_path / "m"))
    aws = _env(client, "aws", KEYS)
    body = _request(client, inventory_id, env_credential_ids=[aws])
    template = client.post("/api/run-templates", json={"name": "cloud", **body})
    assert template.status_code == 201, template.text
    assert template.json()["env_credential_names"] == ["aws"]
    launched = client.post(f"/api/run-templates/{template.json()['id']}/launch").json()
    assert launched["env_credential_names"] == ["aws"]
    again = client.post(f"/api/runs/{launched['id']}/rerun").json()
    assert again["env_credential_ids"] == [aws]

    client.delete(f"/api/credentials/{aws}")
    shown = client.get(f"/api/run-templates/{template.json()['id']}").json()
    assert "environment credential" in shown["missing"]
    refused = client.post(f"/api/run-templates/{template.json()['id']}/launch")
    assert refused.status_code == 409


CLOUD_PLAYBOOK = """\
- hosts: all
  connection: local
  gather_facts: false
  tasks:
    - name: the keys are in the environment
      ansible.builtin.assert:
        that:
          - lookup('env', 'AWS_ACCESS_KEY_ID') | length == 16
          - lookup('env', 'AWS_SECRET_ACCESS_KEY') | length == 30
    - name: show it
      ansible.builtin.debug:
        msg: "secret is {{ lookup('env', 'AWS_SECRET_ACCESS_KEY') }}"
"""


def test_a_real_run_gets_the_variables_and_never_shows_them(client, tmp_path) -> None:
    _login(client)
    inventory_id, _ = _create_inventory_with_host(client, str(tmp_path / "m"))
    aws = _env(client, "aws", KEYS)
    run = client.post(
        "/api/runs",
        json=_request(client, inventory_id, CLOUD_PLAYBOOK, env_credential_ids=[aws]),
    ).json()
    done = _wait_for_completion(client, run["id"], timeout=60)
    assert done["status"] == "success", done["status_reason"]
    log = client.get(f"/api/runs/{run['id']}/log").text
    assert "secret is" in log and SECRET not in log
