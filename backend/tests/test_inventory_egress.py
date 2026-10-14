"""Restricting an inventory's runs to its hosts, end to end on the API's side: the setting and
its extra entries (who may, audited), what a claimed run's job carries, which workers get such
runs, and what the worker reports back. The worker's side is tests/test_egress.py (and
test_egress_root.py for real nftables)."""

import pytest
from fastapi.testclient import TestClient

from tests.conftest import internal_client, make_user_client
from tests.test_inventory_host_keys import _audit, _inventory, _queue, _run
from tests.test_projects import _member, _project
from tests.test_runs import _login

CAPABLE = {"egress_filtered": True, "egress_allowlist": True, "host_keys": True}


def _url(inventory_id: int) -> str:
    return f"/api/inventories/{inventory_id}/egress"


def _restrict(client: TestClient, inventory_id: int, extras: list | None = None) -> None:
    assert client.put(f"{_url(inventory_id)}/mode", json={"restricted": True}).status_code == 200
    if extras is not None:
        response = client.put(f"{_url(inventory_id)}/extras", json={"extras": extras})
        assert response.status_code == 200, response.text


class _Claim:
    def __init__(self, run_id: int, **flags) -> None:
        self.run_id = run_id
        self.http = internal_client()
        body = {"worker_id": "w", "wait_seconds": 0, **CAPABLE, **flags}
        claim = self.http.post("/internal/claim", json=body).json()
        assert claim["run_id"] == run_id
        self.claim_token, self.job_token = claim["claim_token"], claim["job_token"]

    def post(self, action: str, body: dict):
        return self.http.post(
            f"/internal/runs/{self.run_id}/{action}",
            json=body,
            headers={"X-Claim-Token": self.claim_token},
        )

    def job(self):
        return self.post("job", {"job_token": self.job_token})


@pytest.mark.no_worker
def test_restriction_is_off_by_default_and_previews_each_hosts_address(client) -> None:
    _login(client)
    inventory_id = _inventory(
        client,
        {
            "web1": {"ansible_host": "10.0.0.5"},
            "inner": {"ansible_host": "inner.corp", "ansible_ssh_common_args": "-J bastion:2222"},
            "templated": {"ansible_host": "{{ x }}"},
            "localhost": {"ansible_connection": "local"},
        },
    )
    body = client.get(_url(inventory_id)).json()
    assert (body["restricted"], body["extras"]) == (False, [])
    assert body["summary"] == {"hosts": 4, "ok": 1, "local": 1, "indirect": 1, "unknown": 1}
    hosts = {h["host"]: h for h in body["hosts"]}
    assert hosts["web1"]["address"] == "10.0.0.5"
    assert hosts["inner"]["jump_host"] == "bastion:2222"
    assert hosts["templated"]["reason"] == "its address is set by a template"
    only = client.get(_url(inventory_id), params={"problems": True}).json()
    assert [h["host"] for h in only["hosts"]] == ["templated"] and only["total"] == 1
    found = client.get(_url(inventory_id), params={"q": "10.0.0"}).json()
    assert [h["host"] for h in found["hosts"]] == ["web1"]
    assert client.get(f"/api/inventories/{inventory_id}").json()["egress_restricted"] is False


@pytest.mark.no_worker
def test_only_project_admins_change_mode_and_extras(client) -> None:
    _login(client)
    inventory_id = _inventory(client, {"web1": {}})
    url = _url(inventory_id)
    for role in ("operator", "viewer"):
        member = make_user_client(f"{role}1", role)
        assert member.get(url).status_code == 200
        assert member.put(f"{url}/mode", json={"restricted": True}).status_code == 403
        assert member.put(f"{url}/extras", json={"extras": []}).status_code == 403
    other = _project(client, "Elsewhere")
    stranger = _member(client, "stranger", {other: "admin"})
    assert stranger.get(url).status_code == 404
    assert stranger.put(f"{url}/mode", json={"restricted": True}).status_code == 404
    assert client.get(url).json()["restricted"] is False


@pytest.mark.no_worker
def test_changes_are_validated_and_audited(client) -> None:
    _login(client)
    inventory_id = _inventory(client, {})
    url = _url(inventory_id)
    assert client.put(f"{url}/mode", json={"restricted": True}).json() == {"restricted": True}
    assert client.put(f"{url}/mode", json={"restricted": True}).status_code == 200  # no change
    [mode] = _audit("inventory.egress_mode")
    assert mode.detail == {"old": False, "new": True}

    extras = [
        {"target": "10.1.0.0/16", "ports": "443, 8000-8100", "note": "mirrors"},
        {"target": "Pypi.org"},
    ]
    saved = client.put(f"{url}/extras", json={"extras": extras})
    assert saved.json() == [
        {"target": "10.1.0.0/16", "ports": [[443, 443], [8000, 8100]], "note": "mirrors"},
        {"target": "pypi.org", "ports": None, "note": None},
    ]
    bad = client.put(f"{url}/extras", json={"extras": [{"target": "a.lan"}, {"target": "::/0"}]})
    assert bad.status_code == 400 and bad.json()["detail"].startswith("entry 2: ")
    blocked = client.put(f"{url}/extras", json={"extras": [{"target": "169.254.169.254"}]})
    assert blocked.status_code == 400 and "always blocked" in blocked.json()["detail"]
    client.put(f"{url}/extras", json={"extras": [{"target": "pypi.org"}]})
    first, second = _audit("inventory.egress_extras")
    assert first.detail == {"added": ["10.1.0.0/16 443,8000-8100", "pypi.org"], "count": 2}
    assert second.detail == {"removed": ["10.1.0.0/16 443,8000-8100"], "count": 1}
    assert client.put(f"{url}/extras", json={"extras": []}).json() == []


@pytest.mark.no_worker
def test_a_restricted_runs_job_carries_hosts_jump_hosts_and_extras(client) -> None:
    _login(client)
    inventory_id = _inventory(
        client,
        {
            "web1": {"ansible_host": "web1.lan"},
            "inner": {"ansible_host": "inner.corp", "ansible_ssh_common_args": "-J b.lan"},
        },
    )
    unrestricted = _queue(client, inventory_id)
    assert _Claim(unrestricted).job().json()["egress"] is None
    assert _run(unrestricted).egress_restricted is False

    restricted_inventory = _inventory(
        client, {"web1": {"ansible_host": "web1.lan"}}, name="restricted"
    )
    run_id = _queue(client, restricted_inventory)
    _restrict(client, restricted_inventory, [{"target": "10.9.0.0/24", "ports": "443"}])
    job = _Claim(run_id).job().json()
    assert _run(run_id).egress_restricted is True
    assert job["egress"] == {
        "hosts": [{"host": "web1", "address": "web1.lan", "required": True}],
        "jump_hosts": [],
        "extras": [{"target": "10.9.0.0/24", "ports": [[443, 443]]}],
        "warnings": [],
    }


@pytest.mark.no_worker
def test_a_run_with_an_unknown_address_fails_without_running(client) -> None:
    _login(client)
    inventory_id = _inventory(client, {"web1": {}, "web2": {"ansible_host": "{{ x }}"}})
    _restrict(client, inventory_id)
    run_id = _queue(client, inventory_id)
    assert _Claim(run_id).job().status_code == 410
    run = _run(run_id)
    assert run.status == "failed" and run.started_at is None
    assert run.status_reason == (
        "not run: its inventory restricts network egress, and the address of 1 host isn't "
        "known: web2 (its address is set by a template)"
    )


@pytest.mark.no_worker
def test_a_worker_that_cant_restrict_never_gets_a_restricted_run(client) -> None:
    _login(client)
    inventory_id = _inventory(client, {"web1": {}}, name="restricted")
    _restrict(client, inventory_id)
    restricted = _queue(client, inventory_id)
    free = _queue(client, _inventory(client, {"web1": {}}, name="free"))
    http = internal_client()
    for flags in (
        {"host_keys": True},  # a worker from before allowlists
        {"host_keys": True, "egress_allowlist": True},  # allowlists, but no egress filter
        {"host_keys": True, "egress_allowlist": True, "egress_filtered": False},
    ):
        http.post("/internal/heartbeat", json={"worker_id": "old", "runs": [], **flags})
        reason = client.get(f"/api/runs/{restricted}").json()["waiting_reason"]
        assert reason == (
            "Waiting for a worker that can restrict network egress (its egress filter must "
            "be on; upgrade your workers)"
        )
    claimed = http.post("/internal/claim", json={"worker_id": "old", "wait_seconds": 0, **flags})
    assert claimed.json()["run_id"] == free
    assert http.post(
        "/internal/claim", json={"worker_id": "old", "wait_seconds": 0, **flags}
    ).status_code == 204  # fmt: skip
    assert _run(restricted).status == "queued"
    workers = {w["id"]: w for w in client.get("/api/workers").json()}
    assert workers["old"]["egress_allowlist"] is False
    _Claim(restricted)  # a capable worker gets it


@pytest.mark.no_worker
def test_the_restriction_is_fixed_when_the_run_is_claimed(client) -> None:
    _login(client)
    inventory_id = _inventory(client, {"web1": {}})
    run_id = _queue(client, inventory_id)
    _restrict(client, inventory_id)  # after queueing, before the claim: it counts
    claim = _Claim(run_id)
    client.put(f"{_url(inventory_id)}/mode", json={"restricted": False})  # too late
    assert claim.job().json()["egress"] is not None
    assert _run(run_id).egress_restricted is True


@pytest.mark.no_worker
def test_the_resolved_allowlist_and_refused_connections_are_kept(client) -> None:
    _login(client)
    inventory_id = _inventory(client, {"web1": {"ansible_host": "web1.lan"}})
    _restrict(client, inventory_id)
    run_id = _queue(client, inventory_id)
    claim = _Claim(run_id)
    claim.job()
    report = {
        "hosts": [
            {"host": "web1", "address": "web1.lan", "addresses": ["192.0.2.1", "2001:db8::1"]}
        ],
        "jump_hosts": [],
        "extras": [{"target": "10.9.0.0/24", "ports": [[443, 443]], "addresses": ["10.9.0.0/24"]}],
        "unresolved": [],
        "warnings": [],
    }  # fmt: skip
    assert claim.post("egress", report).status_code == 200
    refused = [
        {"address": "203.0.113.5", "protocol": "tcp", "port": 443},
        {"address": "2001:db8::9", "protocol": "udp", "port": 53},
    ]
    completed = claim.post(
        "complete",
        {"last_seq": 0, "status": "failed", "return_code": 2, "egress_refused": refused},
    )
    assert completed.status_code == 200
    out = client.get(f"/api/runs/{run_id}").json()
    assert (out["egress_restricted"], out["egress_addresses"]) == (True, 3)
    assert out["egress_refused"] == refused
    details = client.get(f"/api/runs/{run_id}/egress").json()
    assert details["restricted"] is True and details["refused"] == refused
    assert details["allowlist"]["hosts"][0]["addresses"] == ["192.0.2.1", "2001:db8::1"]
    viewer = make_user_client("viewer1", "viewer")
    assert viewer.get(f"/api/runs/{run_id}/egress").status_code == 200


@pytest.mark.no_worker
def test_bad_egress_reports_are_refused(client) -> None:
    _login(client)
    inventory_id = _inventory(client, {"web1": {}})
    _restrict(client, inventory_id)
    run_id = _queue(client, inventory_id)
    claim = _Claim(run_id)
    claim.job()
    bad_address = {"hosts": [{"host": "web1", "address": "web1", "addresses": ["not-an-ip"]}]}
    assert claim.post("egress", bad_address).status_code == 422
    bad_refused = {"last_seq": 0, "status": "failed", "egress_refused": [
        {"address": "x", "protocol": "tcp", "port": 1}
    ]}  # fmt: skip
    assert claim.post("complete", bad_refused).status_code == 422
    assert claim.post("complete", {"last_seq": 0, "status": "failed"}).status_code == 200
    stranger = internal_client().post(
        f"/internal/runs/{run_id}/egress", json={}, headers={"X-Claim-Token": "nope"}
    )
    assert stranger.status_code == 410
