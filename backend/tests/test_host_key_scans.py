"""Host key scans: what is scanned, the worker protocol (claim, job, complete, reaper), what
an admin sees and trusts from a scan, and a real worker running ssh-keyscan (a fake one on
PATH) as the slot's run process."""

import base64
import os
import stat
import sys
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text, update

from app.db import get_engine, get_sessionmaker
from app.host_key_scans import ScanError, scan_targets
from app.host_keys import HostAddress, fingerprint
from app.models import AuditEvent, HostKeyScan, InventoryHostKey
from app.reaper import reap_scans
from tests.conftest import internal_client, make_user_client
from tests.test_runs import _login


def _blob(body: bytes, key_type: str = "ssh-ed25519") -> str:
    raw = len(key_type).to_bytes(4, "big") + key_type.encode()
    return base64.b64encode(raw + len(body).to_bytes(4, "big") + body).decode()


KEY_A, KEY_B = _blob(b"\x01" * 32), _blob(b"\x02" * 32)
RSA = _blob(b"\x07" * 64, "ssh-rsa")


def _inventory(client: TestClient, hosts: dict[str, dict], name: str = "scan-inv") -> int:
    inventory_id = client.post("/api/inventories", json={"name": name}).json()["id"]
    for hostname, host_vars in hosts.items():
        response = client.post(
            f"/api/inventories/{inventory_id}/hosts", json={"hostname": hostname, "vars": host_vars}
        )
        assert response.status_code == 201, response.text
    return inventory_id


def _scan_row(scan_id: int) -> HostKeyScan:
    with get_sessionmaker()() as db:
        return db.get(HostKeyScan, scan_id)


def _audit(action: str) -> list[AuditEvent]:
    with get_sessionmaker()() as db:
        return list(db.scalars(select(AuditEvent).where(AuditEvent.action == action)))


def test_targets_are_the_hosts_known_addresses_and_extra_names() -> None:
    addresses = {
        "web1": HostAddress("[10.0.0.5]:2222", "ssh", True),
        "web2": HostAddress("web2", "ssh", True),
        "same": HostAddress("web2", "ssh", True),
        "db1": HostAddress(None, "ssh", True, "its address is set by a template"),
        "sw1": HostAddress(None, "network_cli", False, "connects with network_cli, not ssh"),
    }
    assert scan_targets(addresses, None, ["Bastion", "[jump]:22"]) == [
        {"name": "[10.0.0.5]:2222", "host": "10.0.0.5", "port": 2222},
        {"name": "web2", "host": "web2", "port": 22},
        {"name": "bastion", "host": "bastion", "port": 22},
        {"name": "jump", "host": "jump", "port": 22},
    ]
    assert scan_targets(addresses, ["web1"], []) == [
        {"name": "[10.0.0.5]:2222", "host": "10.0.0.5", "port": 2222}
    ]
    for hosts, extra, message in (
        (["nope"], [], "not a host of this inventory"),
        (["db1", "sw1"], [], "none of these hosts"),
        ([], ["-oProxyCommand=x"], "not a host name"),
        ([], ["*.example.com"], "not a host name"),
        ([], [f"h{n}" for n in range(21)], "at most 20 extra"),
    ):
        with pytest.raises(ScanError, match=message):
            scan_targets(addresses, hosts, extra)


@pytest.mark.no_worker
def test_a_scan_is_claimed_reported_and_its_keys_trusted_from_the_scan(client) -> None:
    _login(client)
    inventory_id = _inventory(
        client,
        {
            "web1": {"ansible_host": "10.0.0.5", "ansible_port": 2222},
            "web2": {},
            "web3": {},
        },
    )
    url = f"/api/inventories/{inventory_id}"
    client.post(f"{url}/host-keys/paste", json={"known_hosts": f"web2 ssh-ed25519 {KEY_A}"})
    with get_sessionmaker()() as db:
        db.add(
            InventoryHostKey(
                inventory_id=inventory_id, name="web3", key_type="ssh-ed25519", key_b64=KEY_A,
                fingerprint=fingerprint(KEY_A), source="learned", confirmed=False,
                created_by="run #1",
            )
        )  # fmt: skip
        db.commit()

    started = client.post(f"{url}/host-key-scans", json={"extra": ["bastion"]})
    assert started.status_code == 202, started.text
    scan = started.json()
    assert (scan["status"], scan["targets"]) == ("queued", 4)
    assert scan["wait_reason"] == "No worker is online: start one to scan host keys"
    again = client.post(f"{url}/host-key-scans", json={})
    assert again.json()["id"] == scan["id"]  # one at a time per inventory
    assert len(_audit("inventory.host_key_scan")) == 1

    http = internal_client()
    # A worker that doesn't scan never gets it.
    old = http.post("/internal/claim", json={"worker_id": "old", "wait_seconds": 0})
    assert old.status_code == 204
    claim = http.post(
        "/internal/claim", json={"worker_id": "w", "wait_seconds": 0, "kinds": ["keyscan"]}
    ).json()
    assert (claim["kind"], claim["run_id"]) == ("keyscan", scan["id"])
    token = {"X-Claim-Token": claim["claim_token"]}
    job = http.post(
        f"/internal/keyscans/{scan['id']}/job",
        json={"job_token": claim["job_token"]},
        headers=token,
    ).json()
    assert job["targets"] == [
        {"host": "10.0.0.5", "port": 2222},
        {"host": "web2", "port": 22},
        {"host": "web3", "port": 22},
        {"host": "bastion", "port": 22},
    ]
    heartbeat = {
        "worker_id": "w",
        "runs": [],
        "keyscans": [{"scan_id": scan["id"], "claim_token": claim["claim_token"]}],
    }
    beat = http.post("/internal/heartbeat", json=heartbeat).json()
    assert beat["keyscans"] == [{"scan_id": scan["id"], "state": "ok"}]
    lines = [
        f"[10.0.0.5]:2222 ssh-ed25519 {KEY_A}",
        f"[10.0.0.5]:2222 ssh-rsa {RSA}",
        f"web2 ssh-ed25519 {KEY_B}",  # differs from the trusted key
        f"web3 ssh-ed25519 {KEY_A}",  # the learned key
        f"evil.example ssh-ed25519 {KEY_A}",  # not asked for
        "garbage",
    ]
    done = http.post(
        f"/internal/keyscans/{scan['id']}/complete",
        json={"status": "success", "lines": lines},
        headers=token,
    )
    assert done.status_code == 200

    result = client.get(f"{url}/host-key-scans/{scan['id']}").json()
    assert result["status"] == "success" and result["silent"] == ["bastion"]
    states = {(k["name"], k["key_type"]): (k["state"], k["hosts"]) for k in result["keys"]}
    assert states == {
        ("[10.0.0.5]:2222", "ssh-ed25519"): ("new", ["web1"]),
        ("[10.0.0.5]:2222", "ssh-rsa"): ("new", ["web1"]),
        ("web2", "ssh-ed25519"): ("changed", ["web2"]),
        ("web3", "ssh-ed25519"): ("learned", ["web3"]),
    }
    changed = next(k for k in result["keys"] if k["state"] == "changed")
    assert changed["previous"] == fingerprint(KEY_A)

    trusted = client.post(
        f"{url}/host-keys/trust",
        json={
            "scan_id": scan["id"],
            "keys": [
                {"name": "[10.0.0.5]:2222", "key_type": "ssh-ed25519"},
                {"name": "web3", "key_type": "ssh-ed25519"},
            ],
        },
    )
    assert trusted.status_code == 200, trusted.text
    assert {(k["name"], k["source"], k["confirmed"]) for k in trusted.json()} == {
        ("[10.0.0.5]:2222", "scan", True),
        ("web3", "learned", True),  # trusting a learned key confirms it
    }
    event = _audit("inventory.trust_host_key")[-1]
    assert event.detail["source"] == "scan" and event.detail["count"] == 2
    refused = client.post(
        f"{url}/host-keys/trust",
        json={"scan_id": scan["id"], "keys": [{"name": "evil.example", "key_type": "ssh-ed25519"}]},
    )
    assert refused.status_code == 400

    # Only project admins scan or trust, and only within their inventory.
    operator = make_user_client("operator1", "operator")
    assert operator.post(f"{url}/host-key-scans", json={}).status_code == 403
    assert operator.get(f"{url}/host-key-scans/{scan['id']}").status_code == 403
    other = _inventory(client, {"x": {}}, name="scan-other")
    elsewhere = client.get(f"/api/inventories/{other}/host-key-scans/{scan['id']}")
    assert elsewhere.status_code == 404


@pytest.mark.no_worker
def test_scans_nobody_takes_or_whose_worker_vanished_end_and_old_ones_go(client) -> None:
    _login(client)
    inventory_id = _inventory(client, {"web1": {}})
    queued = client.post(f"/api/inventories/{inventory_id}/host-key-scans", json={}).json()
    with get_engine().begin() as conn:
        conn.execute(update(HostKeyScan).values(queued_at=text("now() - interval '3 minutes'")))
    with get_sessionmaker()() as db:
        assert reap_scans(db)
    row = _scan_row(queued["id"])
    assert row.status == "failed" and row.error.startswith("not scanned: No worker is online")

    lost = client.post(f"/api/inventories/{inventory_id}/host-key-scans", json={}).json()
    claim = (
        internal_client()
        .post("/internal/claim", json={"worker_id": "w", "wait_seconds": 0, "kinds": ["keyscan"]})
        .json()
    )
    assert claim["run_id"] == lost["id"]
    with get_engine().begin() as conn:
        conn.execute(
            update(HostKeyScan)
            .where(HostKeyScan.id == lost["id"])
            .values(lease_expires_at=text("now() - interval '1 second'"))
        )
    with get_sessionmaker()() as db:
        reap_scans(db)
    assert _scan_row(lost["id"]).error.startswith("worker lost")
    gone = internal_client().post(
        f"/internal/keyscans/{lost['id']}/complete",
        json={"status": "success", "lines": []},
        headers={"X-Claim-Token": claim["claim_token"]},
    )
    assert gone.status_code == 410

    with get_engine().begin() as conn:
        conn.execute(update(HostKeyScan).values(finished_at=text("now() - interval '2 hours'")))
    with get_sessionmaker()() as db:
        reap_scans(db)
        assert db.scalars(select(HostKeyScan)).all() == []


FAKE_KEYSCAN = """\
#!{python}
# Prints a key for every host in the -f file, the way ssh-keyscan names them.
import sys
args = sys.argv[1:]
port = int(args[args.index("-p") + 1])
for host in open(args[args.index("-f") + 1]).read().split():
    if host == "silent":
        sys.stderr.write(f"{{host}}: Connection refused\\n")
        continue
    name = host if port == 22 else f"[{{host}}]:{{port}}"
    print(f"# {{host}}:{{port}} SSH-2.0-OpenSSH_10.0")
    print(f"{{name}} ssh-ed25519 {key}")
"""


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX only")
def test_a_real_worker_scans_as_the_run_process(client, tmp_path, monkeypatch) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "ssh-keyscan"
    fake.write_text(FAKE_KEYSCAN.format(python=sys.executable, key=KEY_A))
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    _login(client)
    inventory_id = _inventory(
        client, {"web1": {"ansible_host": "10.0.0.5", "ansible_port": 2222}, "silent": {}}
    )
    url = f"/api/inventories/{inventory_id}/host-key-scans"
    scan = client.post(url, json={}).json()
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = client.get(f"{url}/{scan['id']}").json()
        if result["status"] not in ("queued", "running"):
            break
        time.sleep(0.2)
    assert result["status"] == "success", result
    assert [(k["name"], k["state"]) for k in result["keys"]] == [("[10.0.0.5]:2222", "new")]
    assert result["silent"] == ["silent"]
    assert result["error"] is None  # some host answered; the silent ones are listed
