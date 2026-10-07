"""CREDENTIAL_ENCRYPTION_KEY rotation: several keys (the first encrypts), `reencrypt-secrets`,
and production refusing the example key from .env.example."""

from pathlib import Path

import pytest
from cryptography.fernet import Fernet, InvalidToken
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import LargeBinary, select

from app import cli
from app.config import EXAMPLE_CREDENTIAL_ENCRYPTION_KEY, Settings, get_settings
from app.crypto import encrypt_secret
from app.db import Base, get_sessionmaker
from app.key_rotation import ENCRYPTED_COLUMNS
from app.models import AuditEvent, GitSource, NotificationChannel, User
from app.notifications.channels import seal
from tests.test_runs import _create_credential, _create_vault_password, _login

KEY_A, KEY_B, KEY_C = (Fernet.generate_key().decode() for _ in range(3))
ENV_EXAMPLE = Path(__file__).resolve().parents[2] / ".env.example"


def _use_keys(monkeypatch, *keys: str) -> None:
    monkeypatch.setenv("CREDENTIAL_ENCRYPTION_KEY", ",".join(keys))
    get_settings.cache_clear()


def _tokens() -> dict[str, bytes]:
    """Every stored encrypted value, by table.column#id."""
    db = get_sessionmaker()()
    try:
        found = {}
        for model, columns in ENCRYPTED_COLUMNS:
            for row in db.scalars(select(model)):
                for column in columns:
                    if (token := getattr(row, column)) is not None:
                        found[f"{model.__tablename__}.{column}#{row.id}"] = token
        return found
    finally:
        db.close()


def _plaintexts(key: str) -> dict[str, bytes]:
    fernet = Fernet(key)
    return {name: fernet.decrypt(token) for name, token in _tokens().items()}


def _store_one_of_each(client: TestClient) -> None:
    """A value in every encrypted column (the API where it is simple, rows otherwise)."""
    _create_credential(client)
    env = client.post(
        "/api/credentials", json={"name": "env", "kind": "env", "env": {"API_TOKEN": "t0ken"}}
    )
    assert env.status_code == 201, env.text
    _create_vault_password(client)
    db = get_sessionmaker()()
    try:
        admin = db.scalars(select(User).where(User.username == "admin")).one()
        admin.totp_secret = encrypt_secret(b"JBSWY3DPEHPK3PXP")
        admin.totp_pending_secret = encrypt_secret(b"KRSXG5CTMVRXEZLU")
        db.add(
            GitSource(
                project_id=1,
                name="repo",
                url="https://git.example.com/repo.git",
                auth_kind="https",
                https_username="ci",
                encrypted_token=encrypt_secret(b"git-token"),
                auto_sync_seconds=0,
                enabled=False,
                created_by="admin",
            )
        )
        db.add(
            NotificationChannel(
                project_id=None,
                name="hook",
                kind="slack",
                config_encrypted=seal({"url": "https://hooks.slack.com/services/T/B/x"}),
                events=["run.failed"],
                created_by="admin",
            )
        )
        db.commit()
    finally:
        db.close()


def test_every_binary_column_is_one_the_rotation_rewrites() -> None:
    binary = {
        f"{table.name}.{column.name}"
        for table in Base.metadata.tables.values()
        for column in table.columns
        if isinstance(column.type, LargeBinary)
    }
    rotated = {f"{model.__tablename__}.{c}" for model, cols in ENCRYPTED_COLUMNS for c in cols}
    assert binary == rotated


@pytest.mark.no_worker
def test_a_rotation_moves_every_secret_to_the_new_key(
    client: TestClient, monkeypatch, capsys
) -> None:
    _use_keys(monkeypatch, KEY_A)
    _login(client)
    _store_one_of_each(client)
    before = _plaintexts(KEY_A)
    assert len(before) == 7  # one per column (a credential fills one of its two)

    _use_keys(monkeypatch, KEY_B, KEY_A)
    # Until the rotation, the API reads the old values and writes new ones under the new key.
    _create_vault_password(client, name="written-during-rotation", password="new-pw")
    assert client.get("/api/vault-passwords").status_code == 200
    assert cli.main(["reencrypt-secrets"]) == 0
    out = capsys.readouterr().out
    assert "Re-encrypted 7 secret(s) under the current key; 1 already were." in out
    assert "still lists 1 old key(s)" in out

    _use_keys(monkeypatch, KEY_B)
    after = _plaintexts(KEY_B)
    assert {k: v for k, v in after.items() if k in before} == before
    with pytest.raises(InvalidToken):
        Fernet(KEY_A).decrypt(next(iter(_tokens().values())))

    assert cli.main(["reencrypt-secrets"]) == 0
    assert "Re-encrypted 0 secret(s) under the current key; 8 already were." in (
        capsys.readouterr().out
    )
    db = get_sessionmaker()()
    try:
        events = db.scalars(select(AuditEvent).where(AuditEvent.action == "secrets.reencrypt"))
        (event,) = events.all()  # the second pass changed nothing, so it isn't recorded
        assert event.detail == {"reencrypted": 7}
    finally:
        db.close()


@pytest.mark.no_worker
def test_a_secret_no_key_can_read_stops_the_rotation(
    client: TestClient, monkeypatch, capsys
) -> None:
    _use_keys(monkeypatch, KEY_A)
    _login(client)
    _create_vault_password(client, name="under-a")
    _use_keys(monkeypatch, KEY_C)
    _create_vault_password(client, name="under-c")
    before = _tokens()

    _use_keys(monkeypatch, KEY_B, KEY_A)
    assert cli.main(["reencrypt-secrets"]) == 1
    err = capsys.readouterr().err
    assert "Nothing was changed. vault_passwords.encrypted_password (id " in err
    assert "none of the keys" in err
    assert _tokens() == before


def test_the_key_setting_lists_valid_distinct_keys(monkeypatch) -> None:
    monkeypatch.setenv("CREDENTIAL_ENCRYPTION_KEY", f" {KEY_B} , {KEY_A} ")
    assert Settings(_env_file=None).credential_encryption_keys == [KEY_B, KEY_A]
    for value, message in (
        ("", "is empty"),
        (f"{KEY_A},not-a-key", "key 2 is not a Fernet key"),
        (f"{KEY_A},{KEY_A}", "the same key twice"),
    ):
        monkeypatch.setenv("CREDENTIAL_ENCRYPTION_KEY", value)
        with pytest.raises(ValidationError, match=message) as raised:
            Settings(_env_file=None)
        assert "not-a-key" not in str(raised.value)  # rejected values stay out of the logs


@pytest.fixture
def production(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("AUTH_SECRET_KEY", "s" * 40)
    monkeypatch.setenv("ADMIN_PASSWORD", "a-real-admin-password")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://ansideck:s3cret-db@db/ansideck")
    monkeypatch.setenv("WORKER_TOKEN", "w" * 40)


def test_production_refuses_the_example_key_but_lets_it_be_rotated_away(
    production, monkeypatch
) -> None:
    monkeypatch.setenv("CREDENTIAL_ENCRYPTION_KEY", EXAMPLE_CREDENTIAL_ENCRYPTION_KEY)
    with pytest.raises(ValidationError, match="reencrypt-secrets") as raised:
        Settings(_env_file=None)
    assert EXAMPLE_CREDENTIAL_ENCRYPTION_KEY[-12:] not in str(raised.value)

    monkeypatch.setenv("CREDENTIAL_ENCRYPTION_KEY", f"{KEY_A},{EXAMPLE_CREDENTIAL_ENCRYPTION_KEY}")
    assert Settings(_env_file=None).credential_encryption_keys[0] == KEY_A


def test_production_refuses_what_env_example_ships(production, monkeypatch) -> None:
    """Someone who sets ENVIRONMENT=production on a copy of the root .env.example."""
    for name in ("AUTH_SECRET_KEY", "ADMIN_PASSWORD", "CREDENTIAL_ENCRYPTION_KEY"):
        monkeypatch.delenv(name)
    with pytest.raises(ValidationError, match=r"AUTH_SECRET_KEY .*ADMIN_PASSWORD") as raised:
        Settings(_env_file=ENV_EXAMPLE)
    assert "change-me" not in str(raised.value)

    monkeypatch.setenv("AUTH_SECRET_KEY", "s" * 40)
    monkeypatch.setenv("ADMIN_PASSWORD", "a-real-admin-password")
    with pytest.raises(ValidationError, match="example CREDENTIAL_ENCRYPTION_KEY"):
        Settings(_env_file=ENV_EXAMPLE)


@pytest.mark.parametrize(
    ("name", "value", "refused"),
    [
        ("AUTH_SECRET_KEY", "change-me-to-a-long-random-string", "AUTH_SECRET_KEY"),
        ("AUTH_SECRET_KEY", "s" * 31, "AUTH_SECRET_KEY"),
        ("ADMIN_PASSWORD", "Change-Me", "ADMIN_PASSWORD"),
        ("WORKER_TOKEN", "change-me-to-a-long-random-token", "WORKER_TOKEN"),
        ("METRICS_TOKEN", "change-me-metrics-token-of-32-chars", "METRICS_TOKEN"),
        (
            "DATABASE_URL",
            "postgresql+psycopg://ansideck:change-me-db-password@db/ansideck",
            "the database password",
        ),
    ],
)
def test_production_refuses_placeholders(production, monkeypatch, name, value, refused) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError, match=refused):
        Settings(_env_file=None)


def test_the_session_key_must_not_be_the_worker_token(monkeypatch) -> None:
    monkeypatch.setenv("AUTH_SECRET_KEY", "x" * 40)
    monkeypatch.setenv("WORKER_TOKEN", "x" * 40)
    with pytest.raises(ValidationError, match="AUTH_SECRET_KEY must differ from WORKER_TOKEN"):
        Settings(_env_file=None)
