"""Canary: nothing real reaches the test suite (tests/conftest.py sets this up). If one of these
fails, a test could read a developer's .env or credentials, or write to real data."""

import os
import pwd
import tempfile
import threading
from pathlib import Path

import pytest

from app import config
from app.config import Settings, get_settings
from app.subprocess_env import clean_env
from tests.conftest import ENV_AT_START, SANDBOX, SECRET_LIKE, TEST_DATABASE_URL

pytestmark = pytest.mark.no_worker


def _in_sandbox(path: str) -> bool:
    return Path(path).resolve().is_relative_to(Path(SANDBOX).resolve())


def test_a_dotenv_where_the_tests_run_is_ignored(tmp_path, monkeypatch) -> None:
    (tmp_path / ".env").write_text("AUTH_SECRET_KEY=from-a-real-dotenv\nDATA_DIR=/data\n")
    monkeypatch.chdir(tmp_path)
    settings = Settings()
    assert settings.auth_secret_key != "from-a-real-dotenv"
    assert settings.data_dir != "/data"


def test_the_sandbox_is_a_fresh_temp_dir() -> None:
    assert Path(SANDBOX).name.startswith("ansideck-tests-")
    assert Path(SANDBOX).parent.resolve() in (
        Path("/tmp").resolve(),
        Path(tempfile.gettempdir()).resolve(),
    )
    assert Path(SANDBOX, "home").is_dir()


def test_there_is_no_real_home(tmp_path) -> None:
    """Ansible and ssh in test runs read ~/.ansible.cfg, ~/.ssh/config and known_hosts."""
    real = pwd.getpwuid(os.getuid()).pw_dir
    assert os.environ["HOME"] != real
    assert _in_sandbox(os.environ["HOME"]) and _in_sandbox(str(Path.home()))
    assert clean_env()["HOME"] == os.environ["HOME"]  # what runs get


def test_a_settings_read_under_way_when_a_test_changes_them_is_not_kept(monkeypatch) -> None:
    """The in-process worker reads settings in its own thread all the time. One read that began
    before a test changed the environment must not be cached after the test's cache_clear()."""
    read, release = threading.Event(), threading.Event()

    def slow_settings(**kwargs) -> Settings:
        settings = Settings(**kwargs)
        if threading.current_thread() is not threading.main_thread():
            read.set()  # read the old environment; finishes after the test's change
            release.wait(5)
        return settings

    get_settings.cache_clear()
    monkeypatch.setattr(config, "Settings", slow_settings)
    try:
        worker = threading.Thread(target=get_settings)
        worker.start()
        assert read.wait(5)
        monkeypatch.setenv("SECRETS_STORE_PATH_PREFIX", "changed-by-the-test")
        get_settings.cache_clear()
        release.set()
        worker.join(5)
        assert get_settings().secrets_store_path_prefix == "changed-by-the-test"
    finally:
        release.set()
        get_settings.cache_clear()


def test_data_and_secrets_stay_in_the_sandbox() -> None:
    get_settings.cache_clear()
    try:
        settings = get_settings()
        assert _in_sandbox(settings.data_dir)
        assert _in_sandbox(os.environ["SECRETS_DIR"])
        assert list(Path(os.environ["SECRETS_DIR"]).iterdir()) == []  # never /run/secrets
    finally:
        get_settings.cache_clear()


def test_no_credentials_from_the_shell() -> None:
    leaked = [
        name
        for name in ENV_AT_START
        if SECRET_LIKE.search(name.upper())
        and not name.startswith("TEST_")
        and name not in ("CREDENTIAL_ENCRYPTION_KEY", "SECRETS_DIR")  # the suite's own
    ]
    assert leaked == []


@pytest.mark.parametrize(
    "name",
    ["AWS_SECRET_ACCESS_KEY", "VAULT_TOKEN", "SSH_AUTH_SOCK", "ANSIBLE_CONFIG", "GH_TOKEN",
     "SECRETS_STORE_ROLE_ID", "OIDC_CLIENT_SECRET", "KUBECONFIG", "AZURE_CLIENT_ID",
     "METRICS_TOKEN", "SMTP_PASSWORD", "ADMIN_PASSWORD", "AUTH_SECRET_KEY"],
)  # fmt: skip
def test_the_scrub_covers_the_usual_credentials(name) -> None:
    assert SECRET_LIKE.search(name)


def test_the_database_is_a_throwaway_one() -> None:
    assert TEST_DATABASE_URL.rsplit("/", 1)[-1].split("?")[0].endswith("_test")
    assert os.environ["DATABASE_URL"] == TEST_DATABASE_URL
