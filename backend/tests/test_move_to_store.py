"""Moving a secret stored in AnsiDeck into the secret store (opt-in: SECRETS_STORE_ALLOW_MOVE):
only ever a new secret (read first, then written with check-and-set 0), read back and compared
before the copy here goes, the row locked and unchanged, audited; refused when off, for
references and certificates, and over anything already at the path."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import secret_store
from app.config import get_settings
from app.db import get_sessionmaker
from app.models import AuditEvent, Credential, VaultPassword
from tests.conftest import make_user_client
from tests.test_credentials import _generate_key_pem
from tests.test_runs import _login
from tests.test_secret_store import store  # noqa: F401 - the mocked secret store fixture

DATA = "/v1/secret/data/ansideck/1/"
KEY = _generate_key_pem()
ENV = {"AWS_ACCESS_KEY_ID": "AKIAEXAMPLE12345", "AWS_SECRET_ACCESS_KEY": "env-sentinel-77"}


@pytest.fixture
def moving(store, monkeypatch):  # noqa: F811
    monkeypatch.setenv("SECRETS_STORE_ALLOW_MOVE", "true")
    get_settings.cache_clear()
    yield store
    get_settings.cache_clear()


def _post(client: TestClient, url: str, body: dict) -> int:
    response = client.post(url, json=body)
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _row(model, row_id: int):
    db = get_sessionmaker()()
    try:
        row = db.get(model, row_id)
        db.expunge(row)
        return row
    finally:
        db.close()


def _audit() -> list[tuple[str, str, dict | None]]:
    db = get_sessionmaker()()
    try:
        return [
            (e.action, e.outcome, e.detail)
            for e in db.scalars(
                select(AuditEvent)
                .where(AuditEvent.action.like("%.move_to_store"))
                .order_by(AuditEvent.id)
            )
        ]
    finally:
        db.close()


@pytest.mark.no_worker
def test_a_key_moves_into_the_store_and_leaves_no_copy_here(client: TestClient, moving) -> None:
    _login(client)
    assert client.get("/api/secret-store/info?project_id=1").json()["move_enabled"] is True
    credential = _post(client, "/api/credentials", {"name": "deploy", "private_key": KEY})

    moved = client.post(
        f"/api/credentials/{credential}/move-to-store", json={"store_path": "web/deploy"}
    )
    assert moved.status_code == 200, moved.text
    assert moved.json()["store"] == "external"
    assert moved.json()["store_location"] == "secret/ansideck/1/web/deploy#private_key"
    assert KEY not in moved.text

    assert moving["writes"] == [
        (DATA + "web/deploy", {"options": {"cas": 0}, "data": {"private_key": KEY}})
    ]
    row = _row(Credential, credential)
    assert row.encrypted_private_key is None
    assert (row.store_path, row.store_key) == ("web/deploy", "private_key")
    assert secret_store.resolve_credential(row) == KEY  # runs read it from the store now
    assert _audit() == [
        (
            "credential.move_to_store",
            "success",
            {"location": "secret/ansideck/1/web/deploy#private_key", "version": 1},
        )
    ]


@pytest.mark.no_worker
def test_a_vault_password_and_variables_move_too(client: TestClient, moving) -> None:
    _login(client)
    vault = _post(client, "/api/vault-passwords", {"name": "vault", "password": "pw-sentinel-9"})
    env = _post(client, "/api/credentials", {"name": "aws", "kind": "env", "env": ENV})

    moved = client.post(
        f"/api/vault-passwords/{vault}/move-to-store",
        json={"store_path": "ansible/vault", "store_key": "pw"},
    )
    assert moved.status_code == 200, moved.text
    assert moved.json()["store_location"] == "secret/ansideck/1/ansible/vault#pw"
    assert moving["secrets"][DATA + "ansible/vault"] == {"pw": "pw-sentinel-9"}
    assert _row(VaultPassword, vault).encrypted_password is None

    refused = client.post(
        f"/api/credentials/{env}/move-to-store", json={"store_path": "cloud/aws", "store_key": "x"}
    )
    assert refused.status_code == 400 and "no store_key" in refused.text
    moved = client.post(f"/api/credentials/{env}/move-to-store", json={"store_path": "cloud/aws"})
    assert moved.status_code == 200, moved.text
    assert moving["secrets"][DATA + "cloud/aws"] == ENV  # each variable a key
    row = _row(Credential, env)
    assert (row.encrypted_env, row.env_names, row.store_path) == (None, None, "cloud/aws")
    assert _audit()[-1][2]["names"] == sorted(ENV)


@pytest.mark.no_worker
def test_nothing_already_in_the_store_is_touched(client: TestClient, moving) -> None:
    _login(client)
    credential = _post(client, "/api/credentials", {"name": "deploy", "private_key": KEY})
    url = f"/api/credentials/{credential}/move-to-store"

    moving["secrets"][DATA + "taken"] = {"other": "value"}  # found by the read first
    taken = client.post(url, json={"store_path": "taken"})
    assert taken.status_code == 409 and "already has a secret" in taken.text
    assert moving["writes"] == []

    moving["deleted"].add(DATA + "deleted")  # reads as missing; its metadata stops cas 0
    deleted = client.post(url, json={"store_path": "deleted"})
    assert deleted.status_code == 409 and "already exists" in deleted.text

    moving["write_status"][DATA + "denied"] = (403, {"errors": ["permission denied"]})
    denied = client.post(url, json={"store_path": "denied"})
    assert denied.status_code == 400 and "needs create" in denied.text

    for body in ({"store_path": "../2/x"}, {"store_path": "ok", "store_key": "a/b"}):
        assert client.post(url, json=body).status_code == 400
    assert [(a, o, d["error_kind"]) for a, o, d in _audit()] == [
        ("credential.move_to_store", "failure", "exists"),
        ("credential.move_to_store", "failure", "write_denied"),
    ]
    row = _row(Credential, credential)
    assert row.encrypted_private_key is not None and row.store_path is None


@pytest.mark.no_worker
@pytest.mark.parametrize("changed", ["value", "version"])
def test_a_value_that_doesnt_read_back_the_same_keeps_the_copy_here(
    client: TestClient,
    moving,
    monkeypatch,
    changed: str,
) -> None:
    _login(client)
    vault = _post(client, "/api/vault-passwords", {"name": "vault", "password": "pw-sentinel-9"})
    real = secret_store.read_all_versioned

    def tampered(project_id: int, path: str, deadline=None):
        data, version = real(project_id, path, deadline)
        if changed == "version":  # someone wrote it again in between
            return data, version + 1
        return {key: value + "x" for key, value in data.items()}, version

    reads = iter([real, tampered])  # the check that the path is free, then the read-back

    def read(*args, **kwargs):
        return next(reads)(*args, **kwargs)

    monkeypatch.setattr(secret_store, "read_all_versioned", read)
    moved = client.post(f"/api/vault-passwords/{vault}/move-to-store", json={"store_path": "v"})
    assert moved.status_code == 502 and "nothing changed here" in moved.text
    assert "pw-sentinel-9" not in moved.text
    assert _row(VaultPassword, vault).encrypted_password is not None
    assert _audit()[-1][1:] == (
        "failure",
        {"location": "secret/ansideck/1/v#password", "error_kind": "read_back", "version": 1},
    )


@pytest.mark.no_worker
def test_a_secret_changed_while_moving_is_not_overwritten(
    client: TestClient,
    moving,
    monkeypatch,
) -> None:
    _login(client)
    credential = _post(client, "/api/credentials", {"name": "deploy", "private_key": KEY})
    real = secret_store.create_secret

    def racing(project_id: int, path: str, data: dict, deadline=None) -> int:
        db = get_sessionmaker()()
        db.get(Credential, credential).encrypted_private_key = b"another admin's new key"
        db.commit()
        db.close()
        return real(project_id, path, data, deadline)

    monkeypatch.setattr(secret_store, "create_secret", racing)
    moved = client.post(
        f"/api/credentials/{credential}/move-to-store", json={"store_path": "web/deploy"}
    )
    assert moved.status_code == 409 and "delete it there" in moved.text
    row = _row(Credential, credential)
    assert (row.encrypted_private_key, row.store_path) == (b"another admin's new key", None)


@pytest.mark.no_worker
def test_moving_is_opt_in_and_for_secrets_stored_here_only(
    client: TestClient,
    store,  # noqa: F811
    monkeypatch,
) -> None:
    _login(client)
    credential = _post(client, "/api/credentials", {"name": "deploy", "private_key": KEY})
    url = f"/api/credentials/{credential}/move-to-store"
    assert client.get("/api/secret-store/info?project_id=1").json()["move_enabled"] is False
    off = client.post(url, json={"store_path": "web/deploy"})
    assert off.status_code == 409 and "SECRETS_STORE_ALLOW_MOVE" in off.text

    monkeypatch.setenv("SECRETS_STORE_ALLOW_MOVE", "true")
    get_settings.cache_clear()
    store["secrets"][DATA + "web/ref"] = {"private_key": KEY}
    reference = _post(client, "/api/credentials", {"name": "ref", "store_path": "web/ref"})
    already = client.post(
        f"/api/credentials/{reference}/move-to-store", json={"store_path": "web/x"}
    )
    assert already.status_code == 409 and "already in OpenBao" in already.text
    db = get_sessionmaker()()
    cert = Credential(
        name="cert",
        kind="ssh_cert",
        ssh_mount="ssh",
        ssh_role="ops",
        ssh_principals=["deploy"],
        project_id=1,
    )
    db.add(cert)
    db.commit()
    cert_id = cert.id
    db.close()
    certificate = client.post(
        f"/api/credentials/{cert_id}/move-to-store", json={"store_path": "web/x"}
    )
    assert certificate.status_code == 409

    operator = make_user_client("o1", "operator")
    assert operator.post(url, json={"store_path": "web/deploy"}).status_code == 403
    assert store["writes"] == []
    get_settings.cache_clear()
