from functools import lru_cache

from pydantic import Field, field_validator, model_validator
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

    # Optional OpenID Connect sign-in. Enabled only when issuer, client id and secret are
    # all set (a partial config refuses to start). PUBLIC_URL is the browser-visible base
    # URL of this app; the redirect URI is built from it, never from the request's Host.
    public_url: str = ""
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_scopes: str = "openid email profile"
    oidc_button_label: str = "SSO"
    # SSO never signs in a global admin unless this is set (admins stay local/break-glass).
    oidc_allow_admin: bool = False
    oidc_allowed_email_domains: list[str] = []

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

    @field_validator("public_url")
    @classmethod
    def _strip_public_url(cls, v: str) -> str:
        return v.strip().rstrip("/")

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id and self.oidc_client_secret)

    @model_validator(mode="after")
    def _validate_oidc(self) -> "Settings":
        configured = [self.oidc_issuer, self.oidc_client_id, self.oidc_client_secret]
        if any(configured) and not all(configured):
            raise ValueError(
                "OIDC is partially configured: set OIDC_ISSUER, OIDC_CLIENT_ID and "
                "OIDC_CLIENT_SECRET together (or none of them)."
            )
        if not self.oidc_enabled:
            return self
        if not self.public_url.startswith(("http://", "https://")):
            raise ValueError("OIDC needs PUBLIC_URL (e.g. https://ansideck.example.com).")
        if self.environment.lower() == "production" and not (
            self.public_url.startswith("https://") and self.oidc_issuer.startswith("https://")
        ):
            raise ValueError(
                "ENVIRONMENT=production requires https for PUBLIC_URL and OIDC_ISSUER."
            )
        return self

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
