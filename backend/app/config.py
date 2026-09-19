from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEFAULT_AUTH_SECRET_KEY = "change-me-dev-only-insecure-secret"
_DEFAULT_ADMIN_PASSWORD = "admin"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    auth_secret_key: str = _DEFAULT_AUTH_SECRET_KEY

    # Bootstrap-only: seeds the single admin user in the DB on first startup
    # (only if the users table is empty). Not checked on every login.
    admin_username: str = "admin"
    admin_password: str = _DEFAULT_ADMIN_PASSWORD

    cors_origins: list[str] = ["http://localhost:5173"]
    cookie_secure: bool = False

    data_dir: str = "/data"

    # Audit events older than this are pruned at startup; 0 keeps them forever.
    audit_retention_days: int = 365

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

    @model_validator(mode="after")
    def _refuse_insecure_defaults_in_production(self) -> "Settings":
        if self.environment.lower() == "production":
            insecure = []
            if self.auth_secret_key == _DEFAULT_AUTH_SECRET_KEY:
                insecure.append("AUTH_SECRET_KEY")
            if self.admin_password == _DEFAULT_ADMIN_PASSWORD:
                insecure.append("ADMIN_PASSWORD")
            if insecure:
                raise ValueError(
                    f"ENVIRONMENT=production but {', '.join(insecure)} still has its insecure "
                    "default. Set a real value."
                )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
