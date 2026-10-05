"""Settings from files (Docker secrets): `SECRETS_DIR`, /run/secrets by default."""

import pytest

from app.config import Settings, get_settings


@pytest.fixture
def secrets_dir(tmp_path, monkeypatch):
    for name in (
        "AUTH_SECRET_KEY",
        "ADMIN_PASSWORD",
        "WORKER_TOKEN",
        "DATABASE_URL",
        "ENVIRONMENT",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


def test_a_file_named_after_a_setting_provides_its_value(secrets_dir) -> None:
    (secrets_dir / "auth_secret_key").write_text("a-secret-from-a-file\n")
    # The trailing newline is dropped.
    assert get_settings().auth_secret_key == "a-secret-from-a-file"


def test_the_environment_wins_over_a_file(secrets_dir, monkeypatch) -> None:
    (secrets_dir / "auth_secret_key").write_text("from-the-file")
    monkeypatch.setenv("AUTH_SECRET_KEY", "from-the-environment")
    assert get_settings().auth_secret_key == "from-the-environment"


def test_a_missing_directory_is_ignored(secrets_dir, monkeypatch) -> None:
    monkeypatch.setenv("SECRETS_DIR", str(secrets_dir / "nope"))
    assert get_settings().auth_secret_key  # the development default, and no warning


def test_production_accepts_its_secrets_from_files(secrets_dir, monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("CREDENTIAL_ENCRYPTION_KEY")
    files = {
        "auth_secret_key": "x" * 48,
        "admin_password": "a-real-admin-password",
        "worker_token": "w" * 40,
        "database_url": "postgresql+psycopg://ansideck:a-real-db-password@postgres:5432/ansideck",
        "credential_encryption_key": "R_7QcKt5d6tHB-rDQU_gp4q4YaECbGwV-pehrJOn3NM=",
    }
    for name, value in files.items():
        (secrets_dir / name).write_text(value + "\n")
    settings = Settings(_env_file=None, _secrets_dir=str(secrets_dir))
    assert settings.environment == "production"
    assert settings.worker_token == "w" * 40
    assert settings.credential_encryption_key == files["credential_encryption_key"]
