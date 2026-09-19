from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    auth_secret_key: str = "change-me-dev-only-insecure-secret"

    # Bootstrap-only: seeds the single admin user in the DB on first startup
    # (only if the users table is empty). Not checked on every login.
    admin_username: str = "admin"
    admin_password: str = "admin"

    cors_origins: list[str] = ["http://localhost:5173"]
    cookie_secure: bool = False

    data_dir: str = "/data"

    # Test-only escape hatch: lets requirements.yml reference local tarballs/dirs
    # so tests can install offline. Must stay False in any real deployment —
    # local sources let a user read arbitrary paths inside the container.
    galaxy_allow_local_sources: bool = False

    # No default, deliberately: this encrypts credential secrets at rest, so the
    # app must fail fast at startup if it's unset rather than silently falling
    # back to a shared/insecure key.
    credential_encryption_key: str = Field(
        description="Fernet key used to encrypt credential secrets at rest. "
        'Generate with: python -c "from cryptography.fernet import Fernet; '
        'print(Fernet.generate_key().decode())"'
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
