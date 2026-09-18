import os
from collections.abc import Generator

from cryptography.fernet import Fernet

os.environ.setdefault("CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key().decode())

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.bootstrap import seed_admin_user  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.db import get_engine, get_sessionmaker, init_db  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch) -> Generator[TestClient, None, None]:
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()

    init_db()

    seed_db = get_sessionmaker()()
    seed_admin_user(seed_db)
    seed_db.close()

    yield TestClient(app)

    get_engine.cache_clear()
    get_sessionmaker.cache_clear()
    get_settings.cache_clear()
