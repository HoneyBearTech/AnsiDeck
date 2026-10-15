"""Short-lived SSH certificates (app.ssh_certificates), against a fake OpenBao SSH engine that
signs for real: per-run key pairs, the project-scoped role names, the TTL cap, every refusal
mapped to an error kind, certificates checked before use; the credential kind in the API, the
job a worker gets, the queue's worker capability, and a real run whose ssh-agent holds the
certificate."""

import json
import logging
import secrets
import time
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import run_worker, secret_store, ssh_certificates
from app.config import Settings, get_settings
from app.db import get_sessionmaker
from app.models import AuditEvent, Credential, NotificationAlert
from app.secret_store import SecretStoreError
from app.worker.runner import _ssh_agent_noise
from tests.conftest import internal_client
from tests.test_runs import (
    _create_inventory_with_host,
    _create_playbook,
    _login,
    _wait_for_completion,
)
from tests.test_secret_store import store  # noqa: F401 - the mocked secret store fixture

CA = Ed25519PrivateKey.generate()
SIGN = "/v1/ssh/sign/"


def _sign(public_key: str, principals: list[str], ttl: int, *, key=CA, kind=None) -> str:
    now = int(time.time())
    builder = (
        serialization.SSHCertificateBuilder()
        .public_key(serialization.load_ssh_public_key(public_key.encode()))
        .serial(secrets.randbits(64))
        .type(kind or serialization.SSHCertificateType.USER)
        .key_id(b"vault-token-ansideck-project-1-abc")
        .valid_principals([p.encode() for p in principals])
        .valid_after(now - 30)
        .valid_before(now + ttl)
        .add_extension(b"permit-pty", b"")
    )
    return builder.sign(key).public_bytes().decode() + "\n"


@pytest.fixture
def ssh_store(store, monkeypatch):  # noqa: F811
    """The mocked store with an SSH engine at "ssh/": roles by full name, each with the users
    it allows and an optional maximum TTL (the store refuses longer ones, as OpenBao does)."""
    monkeypatch.setenv("SECRETS_STORE_SSH_MOUNTS", "ssh")
    get_settings.cache_clear()
    store["roles"] = {
        "ansideck-1-web": {"allowed": {"deploy", "ansible"}, "max_ttl": None},
        "ansideck-7-web": {"allowed": {"deploy", "ansible"}, "max_ttl": None},
    }
    store["signed"] = []  # (role, request body)
    previous = secret_store.default_transport

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.raw_path.decode()
        if not path.startswith(SIGN) or path in store["status"] or path in store["once"]:
            return previous.handle_request(request)
        store["requests"].append(request)
        role_name = path.removeprefix(SIGN)
        body = json.loads(request.content)
        role = store["roles"].get(role_name)
        if role is None:
            return httpx.Response(400, json={"errors": [f"Unknown role: {role_name}"]})
        principals = body["valid_principals"].split(",")
        for principal in principals:
            if principal not in role["allowed"]:
                return httpx.Response(
                    400, json={"errors": [f"{principal} is not a valid value for valid_principals"]}
                )
        if role["max_ttl"] is not None and body["ttl"] > role["max_ttl"]:
            return httpx.Response(
                400, json={"errors": [f"ttl is larger than maximum allowed {role['max_ttl']}"]}
            )
        store["signed"].append((role_name, body))
        signed = store.get("forge", _sign)(body["public_key"], principals, body["ttl"])
        return httpx.Response(200, json={"data": {"serial_number": "x", "signed_key": signed}})

    monkeypatch.setattr(secret_store, "default_transport", httpx.MockTransport(handler))
    return store


def _credential(project_id: int = 1, role: str = "web", principals=("deploy", "ansible")):
    return SimpleNamespace(
        id=5,
        name="web",
        kind="ssh_cert",
        project_id=project_id,
        ssh_mount="ssh",
        ssh_role=role,
        ssh_principals=list(principals),
    )


# ---------------------------------------------------------------- issuing


def test_a_run_gets_a_fresh_key_and_a_certificate_for_its_timeout_plus_five_minutes(
    ssh_store,
) -> None:
    issued = ssh_certificates.issue_for_run(
        _credential(), SimpleNamespace(timeout_seconds=3600), secret_store.new_deadline()
    )
    request = ssh_store["requests"][-1]
    assert request.url.raw_path == b"/v1/ssh/sign/ansideck-1-web"
    body = json.loads(request.content)
    assert body["ttl"] == 3600 + 300
    assert body["valid_principals"] == "deploy,ansible"
    assert body["cert_type"] == "user"
    assert body["public_key"].startswith("ssh-ed25519 ") and "key_id" not in body

    key = serialization.load_ssh_private_key(issued.private_key.encode(), None)
    certificate = serialization.load_ssh_public_identity(issued.certificate.encode())
    ours = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    assert body["public_key"].encode() == ours
    info = issued.info
    assert info["serial"] == str(certificate.serial)
    assert info["serial_hex"] == format(certificate.serial, "x")
    assert info["principals"] == ["deploy", "ansible"]
    assert info["location"] == "ssh/sign/ansideck-1-web"
    assert (info["requested_seconds"], info["capped"]) == (3900, False)
    assert (
        info["ca_fingerprint"].startswith("SHA256:")
        and info["key_fingerprint"] != info["ca_fingerprint"]
    )
    assert info["key_id"] == "vault-token-ansideck-project-1-abc"
    assert info["valid_before"] > info["valid_after"]


def test_each_run_gets_its_own_key_pair(ssh_store) -> None:
    run = SimpleNamespace(timeout_seconds=60)
    first, second = (
        ssh_certificates.issue_for_run(_credential(), run, secret_store.new_deadline())
        for _ in range(2)
    )
    assert first.private_key != second.private_key
    assert first.info["key_fingerprint"] != second.info["key_fingerprint"]


def test_the_role_name_comes_from_the_credentials_project(ssh_store) -> None:
    ssh_certificates.issue(_credential(project_id=7), 60, secret_store.new_deadline())
    assert ssh_store["signed"][-1][0] == "ansideck-7-web"
    # A role "named" after another project's still lands in the credential's own project.
    ssh_store["roles"]["ansideck-7-1-web"] = ssh_store["roles"]["ansideck-1-web"]
    ssh_certificates.issue(_credential(project_id=7, role="1-web"), 60, secret_store.new_deadline())
    assert ssh_store["signed"][-1][0] == "ansideck-7-1-web"


@pytest.mark.parametrize("role", ["../x", "a/b", ".x", "x.", "-x", "a b", "", "x" * 65, "a\n"])
def test_bad_role_names_are_refused(role: str) -> None:
    with pytest.raises(ValueError, match="Invalid SSH role name"):
        ssh_certificates.check_role(role)


@pytest.mark.parametrize(
    ("principals", "message"),
    [
        ([], "at least one"),
        (["a,b"], "Invalid principal"),
        (["a b"], "Invalid principal"),
        (["-x"], "Invalid principal"),
        ([f"u{i}" for i in range(17)], "At most 16"),
    ],
)
def test_bad_principals_are_refused(principals: list[str], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        ssh_certificates.check_principals(principals)


def test_principals_are_deduplicated_in_order() -> None:
    assert ssh_certificates.check_principals(["b", " a ", "b", ""]) == ["b", "a"]
    assert ssh_certificates.check_role("db.prod_x-1") == "db.prod_x-1"


def test_only_configured_mounts_sign(ssh_store) -> None:
    with pytest.raises(ValueError, match="isn't one of SECRETS_STORE_SSH_MOUNTS"):
        ssh_certificates.check_mount("ssh-other")
    with pytest.raises(SecretStoreError) as error:
        secret_store.sign_ssh_key(1, "ssh-other", "web", "k", ["deploy"], 60)
    assert error.value.kind == "ssh_disabled"
    assert ssh_store["requests"] == []


def test_a_ttl_over_the_roles_maximum_is_capped_once(ssh_store) -> None:
    ssh_store["roles"]["ansideck-1-web"]["max_ttl"] = 1800
    issued = ssh_certificates.issue(_credential(), 3900, secret_store.new_deadline())
    assert [body["ttl"] for _, body in ssh_store["signed"]] == [1800]
    assert (issued.info["requested_seconds"], issued.info["capped"]) == (3900, True)
    assert len(ssh_store["requests"]) == 2  # refused once, then signed


def test_a_cap_under_a_minute_fails(ssh_store) -> None:
    ssh_store["roles"]["ansideck-1-web"]["max_ttl"] = 30
    with pytest.raises(SecretStoreError) as error:
        ssh_certificates.issue(_credential(), 3900, secret_store.new_deadline())
    assert error.value.kind == "ssh_refused"
    assert ssh_store["signed"] == []


@pytest.mark.parametrize(
    ("status", "body", "kind"),
    [
        (404, {"errors": ["no handler for route 'ssh/sign/x'"]}, "no_ssh_role"),
        (400, {"errors": ["Unknown role: ansideck-1-web"]}, "no_ssh_role"),
        (400, {"errors": ["root is not a valid value for valid_principals"]}, "principal_refused"),
        (400, {"errors": ["cert_type 'user' is not allowed by role"]}, "ssh_refused"),
        (400, {}, "ssh_refused"),
        (403, {"errors": ["permission denied"]}, "denied"),
        (503, {"errors": ["Vault is sealed"]}, "sealed"),
        (200, {"data": {}}, "bad_response"),
        (200, {"data": {"signed_key": "ssh-ed25519 AAAA"}}, "bad_certificate"),
    ],
)
def test_sign_answers_map_to_error_kinds(ssh_store, status: int, body: dict, kind: str) -> None:
    ssh_store["status"][SIGN + "ansideck-1-web"] = (status, body)
    with pytest.raises(SecretStoreError) as error:
        ssh_certificates.issue(_credential(), 60, secret_store.new_deadline())
    assert error.value.kind == kind
    assert str(error.value) == secret_store.explain(kind)  # never the store's own text


def test_each_sign_attempt_uses_its_own_one_use_child_token(ssh_store, monkeypatch) -> None:
    monkeypatch.setenv("SECRETS_STORE_PROJECT_POLICY", "ansideck-project-{project_id}")
    get_settings.cache_clear()
    ssh_store["roles"]["ansideck-1-web"]["max_ttl"] = 600
    ssh_certificates.issue(_credential(), 3900, secret_store.new_deadline())
    paths = [r.url.raw_path.decode() for r in ssh_store["requests"]]
    assert paths == [
        "/v1/auth/token/create",
        SIGN + "ansideck-1-web",
        "/v1/auth/token/create",  # the refused attempt used its token up
        SIGN + "ansideck-1-web",
    ]
    assert ssh_store["child_request"]["policies"] == ["ansideck-project-1"]
    assert ssh_store["child_request"]["num_uses"] == 1
    signs = [r for r in ssh_store["requests"] if r.url.raw_path.startswith(SIGN.encode())]
    assert {r.headers["X-Vault-Token"] for r in signs} == {"child-token"}


@pytest.mark.parametrize(
    "forge",
    [
        # Someone else's key, other principals, a host certificate, another CA's bad signature.
        lambda key, principals, ttl: _sign(
            Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
            .decode(),
            principals,
            ttl,
        ),
        lambda key, principals, ttl: _sign(key, [*principals, "root"], ttl),
        lambda key, principals, ttl: _sign(
            key, principals, ttl, kind=serialization.SSHCertificateType.HOST
        ),
        lambda key, principals, ttl: _sign(key, principals, ttl)[:-40] + "AAAA" * 8 + "\n",
    ],
)
def test_a_certificate_for_another_key_or_other_principals_is_refused(ssh_store, forge) -> None:
    ssh_store["forge"] = forge
    with pytest.raises(SecretStoreError) as error:
        ssh_certificates.issue(_credential(), 60, secret_store.new_deadline())
    assert error.value.kind == "bad_certificate"


def test_nothing_secret_reaches_logs_or_errors(ssh_store, caplog, monkeypatch) -> None:
    caplog.set_level(logging.DEBUG)
    made = []
    real = ssh_certificates.new_key_pair

    def capture():
        made.append(real())
        return made[-1]

    monkeypatch.setattr(ssh_certificates, "new_key_pair", capture)
    ssh_store["status"][SIGN + "ansideck-1-web"] = (400, {"errors": ["failed to parse key"]})
    with pytest.raises(SecretStoreError) as error:
        ssh_certificates.issue(_credential(), 60, secret_store.new_deadline())
    body = made[0][0].splitlines()[1]
    for text in (caplog.text, str(error.value), repr(error.value)):
        assert body not in text and "tok-sentinel" not in text


def test_the_ssh_mounts_setting_is_checked(tmp_path) -> None:
    token = tmp_path / "token"
    token.write_text("t")
    store_settings = {
        "secrets_store_url": "https://bao.lan:8200",
        "secrets_store_token_file": str(token),
    }
    settings = Settings(_env_file=None, **store_settings, secrets_store_ssh_mounts=" ssh, ssh-2 ")
    assert settings.secrets_store_ssh_mount_list == ["ssh", "ssh-2"]
    with pytest.raises(ValueError, match="needs SECRETS_STORE_URL"):
        Settings(_env_file=None, secrets_store_ssh_mounts="ssh")
    for bad in ("a/b", ".x", ",".join(f"m{i}" for i in range(9))):
        with pytest.raises(ValueError, match="SECRETS_STORE_SSH_MOUNTS"):
            Settings(_env_file=None, **store_settings, secrets_store_ssh_mounts=bad)


# ---------------------------------------------------------------- the run process


def test_the_certificate_goes_next_to_ansible_runners_key(tmp_path) -> None:
    key, public = ssh_certificates.new_key_pair()
    certificate = _sign(public, ["deploy"], 60).strip()
    job = {"ssh_key": key, "ssh_certificate": certificate + "\n"}
    run_worker._place_certificate(job, tmp_path)
    placed = tmp_path / "artifacts" / run_worker.RUNNER_IDENT / "ssh_key_data-cert.pub"
    assert placed.read_text() == certificate + "\n"
    assert placed.stat().st_mode & 0o777 == 0o600
    assert job == {"ssh_key": key, "ident": run_worker.RUNNER_IDENT}


@pytest.mark.parametrize(
    "certificate",
    [
        "ssh-ed25519 AAAA",  # a key, not a certificate
        "ssh-ed25519-cert-v01@openssh.com AAAA\nssh-ed25519 BBBB",
        "ssh-ed25519-cert-v01@openssh.com AAAA comment",
        "ssh-ed25519-cert-v01@openssh.com AAAA; rm -rf /",
    ],
)
def test_a_malformed_certificate_refuses_the_run(tmp_path, certificate: str) -> None:
    with pytest.raises(RuntimeError, match="malformed"):
        run_worker._place_certificate({"ssh_key": "k", "ssh_certificate": certificate}, tmp_path)
    assert not (tmp_path / "artifacts").exists()


def test_the_certificate_added_line_is_not_recorded() -> None:
    line = "Certificate added: /tmp/x/artifacts/ansideck/ssh_key_data-cert.pub (vault-token-1)"
    assert _ssh_agent_noise({"event": "verbose", "stdout": line})
    assert not _ssh_agent_noise({"event": "verbose", "stdout": "ok: [web]"})


# ---------------------------------------------------------------- the API


def _create(client: TestClient, name: str = "web", **body):
    return client.post(
        "/api/credentials",
        json={
            "name": name,
            "kind": "ssh_cert",
            "ssh_role": "web",
            "ssh_principals": ["deploy"],
            **body,
        },
    )


def test_an_ssh_certificate_credential_is_checked_by_signing_a_throwaway_key(
    client: TestClient,
    ssh_store,
) -> None:
    _login(client)
    response = _create(client, ssh_principals=["deploy", "ansible", "deploy"])
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["kind"] == "ssh_cert" and body["store"] == "external"
    assert (body["ssh_mount"], body["ssh_role"], body["ssh_role_full"]) == (
        "ssh",
        "web",
        "ansideck-1-web",
    )
    assert body["ssh_principals"] == ["deploy", "ansible"]
    assert body["store_location"] == "ssh/sign/ansideck-1-web"
    assert [body["ttl"] for _, body in ssh_store["signed"]] == [60]

    check = client.post(f"/api/credentials/{body['id']}/check").json()
    assert check["ok"] and check["certificate"]["principals"] == ["deploy", "ansible"]
    assert check["certificate"]["requested_seconds"] == 60

    ssh_store["status"][SIGN + "ansideck-1-web"] = (403, {"errors": ["permission denied"]})
    failed = client.post(f"/api/credentials/{body['id']}/check").json()
    assert (failed["ok"], failed["error_kind"]) == (False, "denied")

    db = get_sessionmaker()()
    events = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.action.in_(["credential.create", "credential.check"]))
        .order_by(AuditEvent.id)
    ).all()
    assert [(e.action, e.outcome) for e in events] == [
        ("credential.create", "success"),
        ("credential.check", "success"),
        ("credential.check", "failure"),
    ]
    assert events[0].detail["location"] == "ssh/sign/ansideck-1-web"
    assert events[0].detail["principals"] == ["deploy", "ansible"]
    assert events[0].detail["test_serial"].isdigit()
    assert events[1].detail == {"serial": check["certificate"]["serial"]}
    assert events[2].detail == {"error_kind": "denied"}
    row = db.get(Credential, body["id"])
    assert row.encrypted_private_key is None and row.store_path is None
    db.close()


def test_ssh_certificates_need_the_store_and_a_configured_mount(
    client: TestClient, ssh_store, monkeypatch
) -> None:
    _login(client)
    other = _create(client, ssh_mount="ssh-other")
    assert other.status_code == 400 and "isn't one of SECRETS_STORE_SSH_MOUNTS" in other.text
    refused = _create(client, ssh_principals=["root"])
    assert refused.status_code == 400
    assert refused.json()["detail"] == (
        "OpenBao: the SSH role doesn't allow one of the credential's principals "
        "(ssh/sign/ansideck-1-web)"
    )
    missing = _create(client, ssh_role="db")
    assert missing.status_code == 400 and "no SSH role by that name" in missing.text
    bad_role = _create(client, ssh_role="a/b")
    assert bad_role.status_code == 400 and "Invalid SSH role name" in bad_role.text
    assert ssh_store["signed"] == []

    monkeypatch.setenv("SECRETS_STORE_SSH_MOUNTS", "")
    get_settings.cache_clear()
    off = _create(client)
    assert off.status_code == 400 and "set SECRETS_STORE_SSH_MOUNTS" in off.text
    info = client.get("/api/secret-store/info?project_id=1").json()
    assert (info["ssh_mounts"], info["ssh_role_prefix"]) == ([], "ansideck-1-")


@pytest.mark.parametrize(
    "extra",
    [
        {"private_key": "k"},
        {"store_path": "web/ssh"},
        {"env": {"A": "b"}},
        {"ssh_role": None},
        {"ssh_principals": []},
    ],
)
def test_ssh_certificate_fields_are_exclusive_to_their_kind(client: TestClient, extra) -> None:
    _login(client)
    assert _create(client, **extra).status_code == 422
    key = client.post("/api/credentials", json={"name": "k", "private_key": "k", "ssh_role": "web"})
    assert key.status_code == 422


def test_credentials_list_filters_by_several_kinds(client: TestClient, ssh_store) -> None:
    _login(client)
    assert _create(client).status_code == 201
    client.post("/api/credentials", json={"name": "env", "kind": "env", "env": {"T": "x" * 20}})
    names = [c["name"] for c in client.get("/api/credentials?kind=ssh&kind=ssh_cert").json()]
    assert names == ["web"]
    assert len(client.get("/api/credentials").json()) == 2


def _run_body(client: TestClient, tmp_path, credential_id: int, playbook: str | None = None):
    name = secrets.token_hex(4)
    inventory_id, _ = _create_inventory_with_host(client, str(tmp_path / "m"), name=name)
    return {
        "playbook_id": _create_playbook(
            client, playbook or "- hosts: all\n  tasks: []\n", name=f"{name}.yml"
        ),
        "inventory_id": inventory_id,
        "credential_id": credential_id,
    }


def _claim(**capabilities):
    http = internal_client()
    response = http.post(
        "/internal/claim",
        json={"worker_id": "w", "wait_seconds": 0, "host_keys": True, **capabilities},
    )
    return http, response


def _job(http, claim: dict):
    return http.post(
        f"/internal/runs/{claim['run_id']}/job",
        json={"job_token": claim["job_token"]},
        headers={"X-Claim-Token": claim["claim_token"]},
    )


@pytest.mark.no_worker
def test_the_job_of_a_certificate_run_carries_a_fresh_key_and_its_certificate(
    client: TestClient, ssh_store, tmp_path
) -> None:
    _login(client)
    credential = _create(client).json()
    run = client.post("/api/runs", json=_run_body(client, tmp_path, credential["id"])).json()

    _, old = _claim()  # a worker that doesn't load certificates gets nothing
    assert old.status_code == 204
    waiting = client.get(f"/api/runs/{run['id']}").json()
    assert waiting["waiting_reason"] == (
        "Waiting for a worker that supports SSH certificates (upgrade your workers)"
    )

    http, claimed = _claim(ssh_certificates=True)
    job = _job(http, claimed.json()).json()
    certificate = serialization.load_ssh_public_identity(job["ssh_certificate"].encode())
    key = serialization.load_ssh_private_key(job["ssh_key"].encode(), None)
    assert certificate.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ) == key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    assert job["ssh_key"].strip() in job["secrets"]  # scrubbed from the run's output
    assert ssh_store["signed"][-1][1]["ttl"] == run["timeout_seconds"] + 300

    shown = client.get(f"/api/runs/{run['id']}").json()["ssh_certificate"]
    assert shown["serial"] == str(certificate.serial)
    assert shown["location"] == "ssh/sign/ansideck-1-web" and "certificate" not in shown
    served = client.get(f"/api/runs/{run['id']}/ssh-certificate")
    assert served.status_code == 200 and served.text == job["ssh_certificate"].strip() + "\n"
    assert "attachment" in served.headers["content-disposition"]

    db = get_sessionmaker()()
    issued = db.scalars(
        select(AuditEvent).where(AuditEvent.action == "credential.certificate_issued")
    ).one()
    assert issued.actor_username == f"run #{run['id']}"
    assert (issued.target_id, issued.project_id) == (credential["id"], 1)
    assert issued.detail["serial"] == shown["serial"] and issued.detail["capped"] is False
    stored = json.dumps([row.detail for row in db.scalars(select(AuditEvent)).all()])
    db.close()
    assert "PRIVATE KEY" not in stored

    key_run = client.post("/api/runs", json=_run_body(client, tmp_path / "k", credential["id"]))
    assert client.get(f"/api/runs/{key_run.json()['id']}/ssh-certificate").status_code == 404


@pytest.mark.no_worker
def test_a_signing_failure_fails_the_run_with_its_reason(
    client: TestClient, ssh_store, tmp_path
) -> None:
    _login(client)
    credential = _create(client).json()
    run = client.post("/api/runs", json=_run_body(client, tmp_path, credential["id"])).json()
    ssh_store["roles"]["ansideck-1-web"]["allowed"] = {"ansible"}  # changed in the store since
    http, claimed = _claim(ssh_certificates=True)
    assert _job(http, claimed.json()).status_code == 410
    failed = client.get(f"/api/runs/{run['id']}").json()
    assert failed["status"] == "failed"
    assert failed["status_reason"] == (
        "not run: could not get an SSH certificate for credential 'web' from OpenBao: "
        "the SSH role doesn't allow one of the credential's principals"
    )
    assert failed["ssh_certificate"] is None


@pytest.mark.no_worker
def test_a_store_outage_while_signing_holds_the_run_and_raises_the_alert(
    client: TestClient, ssh_store, tmp_path
) -> None:
    _login(client)
    credential = _create(client).json()
    run = client.post("/api/runs", json=_run_body(client, tmp_path, credential["id"])).json()
    ssh_store["status"][SIGN + "ansideck-1-web"] = (503, {"errors": ["Vault is sealed"]})
    http, claimed = _claim(ssh_certificates=True)
    assert _job(http, claimed.json()).status_code == 410
    waiting = client.get(f"/api/runs/{run['id']}").json()
    assert waiting["status"] == "queued"  # it waits for the store (app.store_outage)
    assert waiting["waiting_reason"].startswith("Waiting for OpenBao: the secret store is sealed")
    assert _claim(ssh_certificates=True)[1].status_code == 204
    db = get_sessionmaker()()
    alerts = db.scalars(select(NotificationAlert.key)).all()
    db.close()
    assert "secrets.unavailable" in alerts


@pytest.mark.no_worker
def test_a_run_that_cant_be_prepared_gets_no_certificate(
    client: TestClient, ssh_store, tmp_path
) -> None:
    _login(client)
    credential = _create(client).json()
    env = client.post(
        "/api/credentials", json={"name": "aws", "kind": "env", "env": {"T": "x" * 20}}
    ).json()
    body = {**_run_body(client, tmp_path, credential["id"]), "env_credential_ids": [env["id"]]}
    run = client.post("/api/runs", json=body).json()
    client.delete(f"/api/credentials/{env['id']}")
    signed = len(ssh_store["signed"])
    http, claimed = _claim(ssh_certificates=True)
    assert _job(http, claimed.json()).status_code == 410
    assert client.get(f"/api/runs/{run['id']}").json()["status_reason"] == (
        "not run: its credential 'aws' was deleted"
    )
    assert len(ssh_store["signed"]) == signed  # nothing signed for it


@pytest.mark.no_worker
def test_a_run_needs_an_ssh_key_or_certificate_credential(
    client: TestClient, ssh_store, tmp_path, monkeypatch
) -> None:
    _login(client)
    certificate = _create(client).json()
    env = client.post(
        "/api/credentials", json={"name": "aws", "kind": "env", "env": {"T": "x" * 20}}
    ).json()
    body = _run_body(client, tmp_path, env["id"])
    refused = client.post("/api/runs", json=body)
    assert refused.status_code == 400
    assert refused.json()["detail"] == "A run needs an SSH key or SSH certificate credential"
    template = client.post(
        "/api/run-templates",
        json={"name": "t", **body, "credential_id": certificate["id"]},
    )
    assert template.status_code == 201, template.text

    monkeypatch.setenv("SECRETS_STORE_SSH_MOUNTS", "")  # turned off since
    get_settings.cache_clear()
    off = client.post("/api/runs", json={**body, "credential_id": certificate["id"]})
    assert off.status_code == 400 and "set SECRETS_STORE_SSH_MOUNTS" in off.text


AGENT_PLAYBOOK = """\
- hosts: all
  connection: local
  gather_facts: false
  tasks:
    - name: what the run's ssh-agent holds
      ansible.builtin.command: ssh-add -L
      register: agent
      changed_when: false
    - name: show it
      ansible.builtin.debug:
        msg: "agent has {{ agent.stdout_lines | map('split') | map('first') | join(' ') }}"
"""


def test_a_certificate_reaches_the_runs_ssh_agent(
    client: TestClient, ssh_store, tmp_path, monkeypatch
) -> None:
    """A real run (in-process worker, real ansible-runner and ssh-agent): ssh-add loads the
    certificate with the key, ssh would offer it; neither the key nor the "Certificate added"
    line shows in the run's output."""
    _login(client)
    made = []
    real = ssh_certificates.new_key_pair

    def capture():
        made.append(real())
        return made[-1]

    credential = _create(client).json()
    monkeypatch.setattr(ssh_certificates, "new_key_pair", capture)
    run = client.post(
        "/api/runs", json=_run_body(client, tmp_path, credential["id"], AGENT_PLAYBOOK)
    )
    done = _wait_for_completion(client, run.json()["id"], timeout=60)
    run = run.json()
    assert done["status"] == "success", done["status_reason"]
    log = client.get(f"/api/runs/{run['id']}/log").text
    assert "agent has ssh-ed25519 ssh-ed25519-cert-v01@openssh.com" in log
    assert "Certificate added" not in log and "Identity added" not in log
    assert made and made[-1][0].splitlines()[1] not in log
    assert done["ssh_certificate"]["principals"] == ["deploy"]
