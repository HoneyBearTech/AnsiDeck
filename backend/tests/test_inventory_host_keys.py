"""Managed SSH host keys end to end: the inventory API (mode, paste, confirm, remove, who may),
what a claimed run's job carries, what /complete keeps of what a run learned or had refused,
and a real ansible run whose ssh options can't be loosened by inventory vars."""

import base64
import itertools
import json
import os
import stat
import sys
import textwrap

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import host_key_store, internal_api
from app.db import get_sessionmaker
from app.models import AuditEvent, InventoryHostKey, NotificationDelivery, Run
from tests.conftest import internal_client, make_user_client
from tests.test_notifications import _channel
from tests.test_projects import _member, _project
from tests.test_runs import (
    SUCCESS_PLAYBOOK,
    _create_credential,
    _create_playbook,
    _login,
    _wait_for_completion,
)


def _blob(body: bytes, key_type: str = "ssh-ed25519") -> str:
    raw = len(key_type).to_bytes(4, "big") + key_type.encode()
    return base64.b64encode(raw + len(body).to_bytes(4, "big") + body).decode()


KEY_A, KEY_B, KEY_C = (_blob(bytes([n]) * 32) for n in (1, 2, 3))
RSA = _blob(b"\x07" * 64, "ssh-rsa")


def _inventory(client: TestClient, hosts: dict[str, dict], name: str = "hk-inv", **body) -> int:
    response = client.post("/api/inventories", json={"name": name, **body})
    assert response.status_code == 201, response.text
    inventory_id = response.json()["id"]
    for hostname, host_vars in hosts.items():
        created = client.post(
            f"/api/inventories/{inventory_id}/hosts", json={"hostname": hostname, "vars": host_vars}
        )
        assert created.status_code == 201, created.text
    return inventory_id


def _keys(inventory_id: int) -> list[InventoryHostKey]:
    with get_sessionmaker()() as db:
        return list(
            db.scalars(
                select(InventoryHostKey)
                .where(InventoryHostKey.inventory_id == inventory_id)
                .order_by(InventoryHostKey.name, InventoryHostKey.key_type)
            )
        )


def _audit(action: str) -> list[AuditEvent]:
    with get_sessionmaker()() as db:
        return list(db.scalars(select(AuditEvent).where(AuditEvent.action == action)))


def _run(run_id: int) -> Run:
    with get_sessionmaker()() as db:
        return db.get(Run, run_id)


# ------------------------------------------------------------------ the inventory API


@pytest.mark.no_worker
def test_new_inventories_learn_keys_and_report_every_hosts_coverage(client) -> None:
    _login(client)
    inventory_id = _inventory(
        client,
        {
            "web1": {"ansible_host": "10.0.0.5", "ansible_port": 2222},
            "web2": {},
            "db1": {"ansible_host": "{{ lookup('env', 'DB') }}"},
            "local": {"ansible_connection": "local"},
        },
    )
    assert client.get(f"/api/inventories/{inventory_id}").json()["host_key_checking"] == (
        "accept_new"
    )
    listed = client.get(f"/api/inventories/{inventory_id}/host-keys").json()
    assert listed["mode"] == "accept_new" and listed["keys"] == []
    statuses = {h["host"]: (h["name"], h["status"]) for h in listed["hosts"]}
    assert statuses == {
        "web1": ("[10.0.0.5]:2222", "missing"),
        "web2": ("web2", "missing"),
        "db1": (None, "unknown"),
        "local": (None, "not_checked"),
    }
    assert listed["summary"] == {
        "hosts": 4, "trusted": 0, "learned": 0, "missing": 2, "unknown": 1, "not_checked": 1,
    }  # fmt: skip
    found = client.get(f"/api/inventories/{inventory_id}/host-keys", params={"q": "10.0.0"}).json()
    assert [h["host"] for h in found["hosts"]] == ["web1"] and found["total"] == 1


@pytest.mark.no_worker
def test_pasted_keys_are_previewed_trusted_replaced_and_audited(client) -> None:
    _login(client)
    inventory_id = _inventory(client, {"web1": {"ansible_host": "10.0.0.5", "ansible_port": 2222}})
    url = f"/api/inventories/{inventory_id}/host-keys"
    pasted = f"[10.0.0.5]:2222,web1 ssh-ed25519 {KEY_A}\n*.example.com ssh-ed25519 {KEY_A}\n"

    preview = client.post(f"{url}/paste", json={"known_hosts": pasted, "dry_run": True}).json()
    assert [(k["name"], k["change"], k["hosts"]) for k in preview["keys"]] == [
        ("[10.0.0.5]:2222", "new", ["web1"]),
        ("web1", "new", []),  # a key nobody connects to by that name (kept: a jump host, say)
    ]
    assert len(preview["warnings"]) == 1 and _keys(inventory_id) == []

    assert client.post(f"{url}/paste", json={"known_hosts": pasted}).status_code == 200
    keys = _keys(inventory_id)
    assert [(k.name, k.source, k.confirmed, k.created_by) for k in keys] == [
        ("[10.0.0.5]:2222", "paste", True, "admin"),
        ("web1", "paste", True, "admin"),
    ]
    [event] = _audit("inventory.trust_host_key")
    assert event.detail["count"] == 2 and event.target_id == inventory_id

    # A new key of the same type replaces the old one; the same key again changes nothing.
    again = f"[10.0.0.5]:2222 ssh-ed25519 {KEY_B}\nweb1 ssh-ed25519 {KEY_A}\n"
    result = client.post(f"{url}/paste", json={"known_hosts": again}).json()
    assert [(k["change"], k["previous"]) for k in result["keys"]] == [
        ("replace", keys[0].fingerprint),
        ("same", None),
    ]
    assert _keys(inventory_id)[0].key_b64 == KEY_B
    assert _audit("inventory.trust_host_key")[-1].detail["keys"] == [
        {
            "name": "[10.0.0.5]:2222",
            "key_type": "ssh-ed25519",
            "fingerprint": _keys(inventory_id)[0].fingerprint,
            "previous": keys[0].fingerprint,
        }
    ]
    listed = client.get(url).json()
    assert listed["hosts"][0]["status"] == "trusted"
    assert client.get(url, params={"untrusted": True}).json()["hosts"] == []
    assert {k["name"]: k["hosts"] for k in listed["keys"]} == {
        "[10.0.0.5]:2222": ["web1"],
        "web1": [],
    }

    bad = client.post(f"{url}/paste", json={"known_hosts": "|1|abc=|def= ssh-ed25519 AAAA"})
    assert bad.status_code == 400 and "No usable key" in bad.json()["detail"]


@pytest.mark.no_worker
def test_keys_are_capped_per_inventory(client, monkeypatch) -> None:
    _login(client)
    inventory_id = _inventory(client, {})
    monkeypatch.setattr(host_key_store, "MAX_KEYS", 2)
    url = f"/api/inventories/{inventory_id}/host-keys/paste"
    three = "".join(f"h{n} ssh-ed25519 {KEY_A}\n" for n in range(3))
    response = client.post(url, json={"known_hosts": three})
    assert response.status_code == 400 and "at most 2" in response.json()["detail"]
    assert _keys(inventory_id) == []


@pytest.mark.no_worker
def test_only_project_admins_manage_host_keys(client) -> None:
    _login(client)
    inventory_id = _inventory(client, {"web1": {}})
    url = f"/api/inventories/{inventory_id}/host-keys"
    client.post(f"{url}/paste", json={"known_hosts": f"web1 ssh-ed25519 {KEY_A}"})
    [key] = _keys(inventory_id)

    for role in ("operator", "viewer"):
        member = make_user_client(f"{role}1", role)
        assert member.get(url).status_code == 200
        assert member.put(f"{url}/mode", json={"mode": "off"}).status_code == 403
        paste = member.post(f"{url}/paste", json={"known_hosts": f"web1 ssh-rsa {RSA}"})
        assert paste.status_code == 403
        assert member.post(f"{url}/confirm", json={"ids": [key.id]}).status_code == 403
        assert member.delete(f"{url}/{key.id}").status_code == 403
    # An operator can create inventories but not choose their mode.
    operator = make_user_client("operator2", "operator")
    created = operator.post(
        "/api/inventories", json={"name": "op-inv", "host_key_checking": "off"}
    ).json()
    assert created["host_key_checking"] == "accept_new"

    # Another project's admin doesn't even see it.
    other = _project(client, "Elsewhere")
    stranger = _member(client, "stranger", {other: "admin"})
    assert stranger.get(url).status_code == 404
    assert stranger.put(f"{url}/mode", json={"mode": "off"}).status_code == 404
    assert stranger.delete(f"{url}/{key.id}").status_code == 404

    # A key id from another inventory is not found through this one.
    default = client.get(f"/api/inventories/{inventory_id}").json()["project_id"]
    elsewhere = _inventory(client, {}, name="hk-other", project_id=default)
    assert client.delete(f"/api/inventories/{elsewhere}/host-keys/{key.id}").status_code == 404
    assert client.delete(f"{url}/{key.id}").status_code == 204
    assert _keys(inventory_id) == []
    [removed] = _audit("inventory.remove_host_key")
    assert removed.detail["name"] == "web1" and removed.actor_username == "admin"


@pytest.mark.no_worker
def test_mode_changes_are_audited(client) -> None:
    _login(client)
    inventory_id = _inventory(client, {})
    url = f"/api/inventories/{inventory_id}/host-keys/mode"
    assert client.put(url, json={"mode": "strict"}).json() == {"mode": "strict"}
    assert client.put(url, json={"mode": "strict"}).status_code == 200  # no change, no audit
    assert client.put(url, json={"mode": "loose"}).status_code == 422
    [event] = _audit("inventory.host_key_mode")
    assert event.detail == {"old": "accept_new", "new": "strict"}


# ------------------------------------------------------------------ jobs and results


_names = itertools.count()


def _queue(client: TestClient, inventory_id: int) -> int:
    n = next(_names)
    response = client.post(
        "/api/runs",
        json={
            "playbook_id": _create_playbook(client, SUCCESS_PLAYBOOK, name=f"p{n}.yml"),
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client, name=f"c{n}"),
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


class _Claim:
    def __init__(self, run_id: int) -> None:
        self.run_id = run_id
        self.http = internal_client()
        claim = self.http.post(
            "/internal/claim", json={"worker_id": "w", "wait_seconds": 0, "host_keys": True}
        ).json()
        assert claim["run_id"] == run_id
        self.claim_token, self.job_token = claim["claim_token"], claim["job_token"]

    def post(self, action: str, body: dict):
        return self.http.post(
            f"/internal/runs/{self.run_id}/{action}",
            json=body,
            headers={"X-Claim-Token": self.claim_token},
        )

    def job(self) -> dict:
        return self.post("job", {"job_token": self.job_token}).json()

    def complete(self, **extra):
        body = {"last_seq": 0, "status": "failed", "return_code": 4, **extra}
        return self.post("complete", body)


@pytest.mark.no_worker
@pytest.mark.parametrize("mode", ["off", "accept_new", "strict"])
def test_a_runs_job_carries_the_keys_its_mode_trusts(client, mode) -> None:
    _login(client)
    inventory_id = _inventory(client, {"web1": {}, "web2": {}})
    url = f"/api/inventories/{inventory_id}/host-keys"
    client.post(f"{url}/paste", json={"known_hosts": f"web1 ssh-ed25519 {KEY_A}"})
    with get_sessionmaker()() as db:
        db.add(
            InventoryHostKey(
                inventory_id=inventory_id, name="web2", key_type="ssh-ed25519", key_b64=KEY_B,
                fingerprint="SHA256:x", source="learned", confirmed=False, created_by="run #0",
            )
        )  # fmt: skip
        db.commit()
    run_id = _queue(client, inventory_id)
    client.put(f"{url}/mode", json={"mode": mode})  # applies to runs claimed from now on

    job = _Claim(run_id).job()
    assert _run(run_id).host_key_checking == mode
    if mode == "off":
        assert job["host_keys"] is None
    elif mode == "strict":
        assert job["host_keys"] == {"mode": "strict", "known_hosts": f"web1 ssh-ed25519 {KEY_A}\n"}
    else:
        assert job["host_keys"] == {
            "mode": "accept_new",
            "known_hosts": f"web1 ssh-ed25519 {KEY_A}\nweb2 ssh-ed25519 {KEY_B}\n",
        }


@pytest.mark.no_worker
def test_a_worker_that_doesnt_check_host_keys_only_gets_runs_that_dont(client) -> None:
    _login(client)
    checked = _queue(client, _inventory(client, {"web1": {}}, name="checked"))
    unchecked_inventory = _inventory(client, {"web1": {}}, name="unchecked")
    client.put(f"/api/inventories/{unchecked_inventory}/host-keys/mode", json={"mode": "off"})
    unchecked = _queue(client, unchecked_inventory)

    old = {"worker_id": "old", "wait_seconds": 0}
    claimed = internal_client().post("/internal/claim", json=old).json()
    assert claimed["run_id"] == unchecked  # the older run waits for an upgraded worker
    assert internal_client().post("/internal/claim", json=old).status_code == 204
    assert _run(checked).status == "queued"


@pytest.mark.no_worker
def test_learned_keys_are_kept_only_for_the_runs_own_hosts_that_had_none(client) -> None:
    _login(client)
    inventory_id = _inventory(
        client,
        {"web1": {"ansible_host": "10.0.0.5", "ansible_port": 2222}, "web2": {}, "web3": {}},
    )
    url = f"/api/inventories/{inventory_id}/host-keys"
    client.post(f"{url}/paste", json={"known_hosts": f"web3 ssh-rsa {RSA}"})
    run_id = _queue(client, inventory_id)
    claim = _Claim(run_id)
    claim.job()
    learned = [
        f"[10.0.0.5]:2222 ssh-ed25519 {KEY_A}",  # kept
        f"[10.0.0.5]:2222 ssh-rsa {RSA}",  # one key per address and run
        f"web2 ssh-ed25519 {KEY_B}",  # kept
        f"web3 ssh-ed25519 {KEY_C}",  # web3 already has a key (of another type)
        f"github.com ssh-ed25519 {KEY_C}",  # not a host of this inventory
        f"* ssh-ed25519 {KEY_C}",
        f"@cert-authority * ssh-ed25519 {KEY_C}",
        "not a line",
    ]
    assert claim.complete(status="success", return_code=0, learned_host_keys=learned).json() == {}

    keys = {(k.name, k.key_type): k for k in _keys(inventory_id)}
    assert sorted(keys) == [
        ("[10.0.0.5]:2222", "ssh-ed25519"),
        ("web2", "ssh-ed25519"),
        ("web3", "ssh-rsa"),
    ]
    learned_key = keys[("web2", "ssh-ed25519")]
    assert (learned_key.source, learned_key.confirmed, learned_key.run_id) == (
        "learned", False, run_id,
    )  # fmt: skip
    assert learned_key.created_by == f"run #{run_id}"
    run = _run(run_id)
    assert (run.status, run.host_keys_learned) == ("success", 2)
    [event] = _audit("inventory.host_key_learned")
    assert event.actor_username == f"run #{run_id}" and event.detail["count"] == 2
    assert {k["host"] for k in event.detail["keys"]} == {"web1", "web2"}

    listed = client.get(url).json()
    assert {h["host"]: h["status"] for h in listed["hosts"]} == {
        "web1": "learned", "web2": "learned", "web3": "trusted",
    }  # fmt: skip
    ids = [k["id"] for k in listed["keys"] if not k["confirmed"]]
    confirmed = client.post(f"{url}/confirm", json={"ids": [*ids, 999_999]}).json()
    assert sorted(k["name"] for k in confirmed) == ["[10.0.0.5]:2222", "web2"]
    assert all(k["confirmed"] and k["confirmed_by"] == "admin" for k in confirmed)
    assert _audit("inventory.confirm_host_key")[0].detail["count"] == 2

    # A run that learned nothing says so.
    quiet = _queue(client, inventory_id)
    claim = _Claim(quiet)
    claim.job()
    claim.complete(status="success", return_code=0)
    assert _run(quiet).host_keys_learned == 0

    # Nothing is learned in strict mode (ssh doesn't learn there, so it's planted).
    client.put(f"{url}/mode", json={"mode": "strict"})
    strict_run = _queue(client, inventory_id)
    claim = _Claim(strict_run)
    claim.job()
    claim.complete(learned_host_keys=[f"web9 ssh-ed25519 {KEY_A}"])
    assert len(_keys(inventory_id)) == 3 and _run(strict_run).host_keys_learned is None


@pytest.mark.no_worker
def test_refused_host_keys_are_kept_explained_audited_and_notified(client) -> None:
    _login(client)
    inventory_id = _inventory(client, {"web1": {}, "web2": {}})
    run_id = _queue(client, inventory_id)
    channel = _channel(_run(run_id).project_id, events=("inventory.host_key_changed",))
    claim = _Claim(run_id)
    claim.job()
    presented = "SHA256:" + "A" * 43
    problems = [
        {"host": "web1", "problem": "changed", "name": "web1", "key_type": "ED25519",
         "presented": presented},
        {"host": "web2", "problem": "unknown", "name": "web2", "key_type": "ED25519"},
    ]  # fmt: skip
    assert claim.complete(host_key_problems=problems).status_code == 200

    run = client.get(f"/api/runs/{run_id}").json()
    assert run["status_reason"] == "SSH host key changed for web1, web2"
    assert [p["host"] for p in run["host_key_problems"]] == ["web1", "web2"]
    assert run["host_key_problems"][0]["presented"] == presented
    assert run["host_key_checking"] == "accept_new"
    [event] = _audit("inventory.host_key_refused")
    assert event.outcome == "failure" and event.detail["count"] == 2
    with get_sessionmaker()() as db:
        [delivery] = db.scalars(
            select(NotificationDelivery).where(NotificationDelivery.channel_id == channel)
        ).all()
    assert delivery.event == "inventory.host_key_changed"
    assert [h["host"] for h in delivery.payload["hosts"]] == ["web1"]  # changed keys only

    bad = {"host": "web1", "problem": "changed", "presented": "not a fingerprint"}
    rejected = _Claim(_queue(client, inventory_id))
    rejected.job()
    assert rejected.complete(host_key_problems=[bad]).status_code == 422


@pytest.mark.no_worker
def test_bad_host_key_data_never_keeps_a_run_from_finishing(client, monkeypatch) -> None:
    _login(client)
    run_id = _queue(client, _inventory(client, {"web1": {}}))
    claim = _Claim(run_id)
    claim.job()

    def broken(*_args):
        raise RuntimeError("boom")

    monkeypatch.setattr(internal_api, "record_learned", broken)
    response = claim.complete(status="success", learned_host_keys=[f"web1 ssh-ed25519 {KEY_A}"])
    assert response.status_code == 200
    assert _run(run_id).status == "success"
    assert _audit("inventory.host_key_learned") == []


# ------------------------------------------------------------------ a real run

FAKE_SSH = """\
#!{python}
# Records its arguments, learns a key the way ssh's accept-new would, then refuses the host
# the way ssh does when a key changed.
import json, os, sys
args = sys.argv[1:]
with open({log!r}, "a") as log:
    log.write(json.dumps(args) + "\\n")
files = next(a.split("=", 1)[1] for a in args if a.startswith("UserKnownHostsFile="))
with open(files.split()[0], "a") as learned:
    learned.write("[10.0.0.5]:2222 ssh-ed25519 {key}\\n")
sys.stderr.write(
    "The fingerprint for the ED25519 key sent by the remote host is\\n"
    "SHA256:lb3T+CbqsTi3pCqDEQBmfHd/c/jIK875yJAZ+F10Eyo.\\n"
    "Host key for [10.0.0.5]:2222 has changed and you have requested strict checking.\\n"
    "Host key verification failed.\\n"
)
sys.exit(255)
"""


def _options(args: list[str]) -> list[tuple[str, str]]:
    found = []
    for flag, value in itertools.pairwise(args):
        if flag == "-o" and "=" in value:
            name, setting = value.split("=", 1)
            found.append((name.lower(), setting))
    return found


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX only")
def test_inventory_vars_cant_loosen_a_real_runs_ssh_options(client, tmp_path, monkeypatch) -> None:
    """ansible runs our fake ssh (first on PATH) with the run's options first, whatever the
    host's vars say; what it learned and the refusal it printed reach the run."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "ssh-args.jsonl"
    fake = bin_dir / "ssh"
    fake.write_text(FAKE_SSH.format(python=sys.executable, log=str(log), key=KEY_A))
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")

    _login(client)
    hostile = {
        "ansible_host": "10.0.0.5",
        "ansible_port": 2222,
        "ansible_host_key_checking": False,
        "ansible_ssh_common_args": "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
        "ansible_ssh_extra_args": "-o GlobalKnownHostsFile=/tmp/planted",
        "ansible_ssh_args": "-o StrictHostKeyChecking=no",
        "ansible_ssh_executable": "/bin/false",
        "ansible_ssh_retries": 0,
    }
    inventory_id = _inventory(client, {"web1": hostile})
    playbook = textwrap.dedent(
        """\
        - hosts: all
          gather_facts: false
          vars:
            ansible_ssh_args: -o StrictHostKeyChecking=no
          tasks:
            - ansible.builtin.ping:
        """
    )
    response = client.post(
        "/api/runs",
        json={
            "playbook_id": _create_playbook(client, playbook, name="ping.yml"),
            "inventory_id": inventory_id,
            "credential_id": _create_credential(client),
            "extra_vars": {"ansible_ssh_args": "-o StrictHostKeyChecking=no"},
        },
    )
    assert response.status_code == 201, response.text
    run = _wait_for_completion(client, response.json()["id"], timeout=60)

    assert run["status"] == "failed"
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert calls, "ansible never ran ssh"
    for args in calls:
        options = _options(args)
        first = {}
        for name, value in options:
            first.setdefault(name, value)
        assert first["stricthostkeychecking"] == "accept-new"
        files = first["userknownhostsfile"].split()
        assert [os.path.basename(f) for f in files] == ["learned_known_hosts", "known_hosts"]
        assert first["globalknownhostsfile"] == "/dev/null"
        assert ("stricthostkeychecking", "no") in options  # still there, but after ours
    assert run["host_key_problems"] == [
        {
            "host": "web1",
            "problem": "changed",
            "name": "[10.0.0.5]:2222",
            "key_type": "ED25519",
            "presented": "SHA256:lb3T+CbqsTi3pCqDEQBmfHd/c/jIK875yJAZ+F10Eyo",
        }
    ]
    assert run["status_reason"] == "SSH host key changed for web1"
    assert run["host_keys_learned"] == 1
    [key] = _keys(inventory_id)
    assert (key.name, key.key_b64, key.source) == ("[10.0.0.5]:2222", KEY_A, "learned")
