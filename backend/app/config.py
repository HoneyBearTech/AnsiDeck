import os
import re
from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url

_DEFAULT_AUTH_SECRET_KEY = "change-me-dev-only-insecure-secret"  # noqa: S105 - dev default, refused in production
_DEFAULT_ADMIN_PASSWORD = "admin"  # noqa: S105 - dev default, refused in production
_DEFAULT_DB_PASSWORD = "ansideck"  # noqa: S105 - dev default, refused in production
# The worker has its own copy (app.worker.settings must not import this module).
DEFAULT_WORKER_TOKEN = "change-me-dev-only-worker-token"  # noqa: S105 - dev default, refused in production
MIN_WORKER_TOKEN_LENGTH = 32
MIN_AUTH_SECRET_KEY_LENGTH = 32
# The key published in .env.example: anyone can decrypt with it. Production may keep it only as an
# old key, to re-encrypt what it encrypted (see docs/upgrading.md).
EXAMPLE_CREDENTIAL_ENCRYPTION_KEY = "R_7QcKt5d6tHB-rDQU_gp4q4YaECbGwV-pehrJOn3NM="


def is_placeholder(value: str) -> bool:
    """A value copied from .env.example without being changed ("change-me...")."""
    return value.strip().lower().startswith("change-me")


class Settings(BaseSettings):
    # Errors must not print what they rejected: it is often a secret (and lands in the logs).
    model_config = SettingsConfigDict(
        env_file=".env", extra="ignore", populate_by_name=True, hide_input_in_errors=True
    )

    environment: str = "development"
    auth_secret_key: str = _DEFAULT_AUTH_SECRET_KEY

    # Bootstrap-only: seeds the single admin user in the DB on first startup
    # (only if the users table is empty). Not checked on every login.
    admin_username: str = "admin"
    admin_password: str = _DEFAULT_ADMIN_PASSWORD

    cors_origins: list[str] = ["http://localhost:5173"]
    # Host names the API answers to (a request for any other gets 400), so a DNS-rebinding
    # page can't reach a backend on localhost. Empty: localhost, 127.0.0.1 and the compose
    # service name in development, any host in production (where the reverse proxy decides).
    allowed_hosts: list[str] = []
    cookie_secure: bool = False

    data_dir: str = "/data"

    # Postgres (psycopg 3). The default matches the dev compose `postgres` service as seen
    # from the host (its port is published on 127.0.0.1:5433); compose passes its own URL.
    database_url: str = (
        f"postgresql+psycopg://ansideck:{_DEFAULT_DB_PASSWORD}@localhost:5433/ansideck"
    )

    # PUBLIC_URL is the browser-visible base URL of this app; the SSO redirect URIs are
    # built from it, never from the request's Host.
    public_url: str = ""

    # Optional OpenID Connect sign-in. Enabled only when issuer, client id and secret are
    # all set (a partial config refuses to start).
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_scopes: str = "openid email profile"
    oidc_button_label: str = "SSO"

    # Optional native GitHub sign-in (an OAuth App; GitHub is not an OIDC provider). Enabled
    # only when the client id and secret are both set. The URLs are overridable for GitHub
    # Enterprise Server (and for tests).
    github_client_id: str = ""
    github_client_secret: str = ""
    github_url: str = "https://github.com"
    github_api_url: str = "https://api.github.com"
    github_button_label: str = "GitHub"

    # Shared by every SSO provider. SSO never signs in a global admin unless this is set
    # (admins stay local/break-glass). The OIDC_* names came first and keep working.
    sso_allow_admin: bool = Field(
        default=False, validation_alias=AliasChoices("SSO_ALLOW_ADMIN", "OIDC_ALLOW_ADMIN")
    )
    sso_allowed_email_domains: list[str] = Field(
        default=[],
        validation_alias=AliasChoices("SSO_ALLOWED_EMAIL_DOMAINS", "OIDC_ALLOWED_EMAIL_DOMAINS"),
    )

    # Workers reach the API only through the internal API (never published or proxied),
    # authenticated with this shared token. Compose sets the host to 0.0.0.0 so workers on
    # the internal network can connect; the default keeps a bare local run private.
    worker_token: str = DEFAULT_WORKER_TOKEN
    internal_api_enabled: bool = True
    internal_api_host: str = "127.0.0.1"
    internal_api_port: int = 8001
    # A worker's claim on a run lasts this long past its latest heartbeat.
    run_lease_seconds: int = 60

    # Prometheus metrics (app.metrics_api): served on a port of their own, only when a token
    # is set, to scrapers that send it as a bearer token. Never publish or proxy the port.
    metrics_token: str = ""
    metrics_host: str = "127.0.0.1"
    metrics_port: int = 8002

    # Peers whose X-Real-IP header names the client (the frontend's nginx): host names (looked up
    # again every 30 s, so a recreated container's new address counts), addresses or CIDRs,
    # comma-separated. Loopback always counts. Anyone else's header is ignored: a worker's
    # playbook could otherwise pick its own address and dodge the login throttles.
    trusted_proxy_hosts: str = "frontend"

    # Audit events older than this are pruned at startup; 0 keeps them forever.
    audit_retention_days: int = 365

    # Notifications (app.notifications). Webhooks to loopback, private, link-local and other
    # non-public addresses are refused unless their host name, address or CIDR is listed here
    # (comma-separated), e.g. "ntfy.lan,192.168.1.0/24" for a self-hosted service.
    notify_allowed_private_hosts: str = ""
    # Ops notifications: a worker is reported offline after this long without a heartbeat
    # (it shows offline after 30 s; this rides out restarts), and the queue as stuck once a
    # run has waited this long for a worker or a galaxy install.
    notify_worker_offline_seconds: int = Field(120, ge=31)
    notify_queue_stuck_minutes: int = Field(10, ge=1)
    # Email notifications go through this one SMTP server; email channels hold recipients
    # only. Unset: no email channels.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_tls: Literal["starttls", "tls", "none"] = "starttls"

    # Git sources (app.git_sync). Remotes on loopback, private, link-local and other non-public
    # addresses are refused unless their host name, address or CIDR is listed here
    # (comma-separated), e.g. "gitea.lan,192.168.1.0/24" for a self-hosted forge.
    git_allowed_private_hosts: str = ""
    git_sync_timeout_seconds: int = Field(300, ge=10)
    git_max_repo_mb: int = Field(500, ge=1)  # the fetch mirror on disk
    git_max_snapshot_mb: int = Field(50, ge=1)  # what one run gets
    git_max_files: int = Field(20_000, ge=1)
    git_max_playbooks: int = Field(500, ge=1)  # per source
    git_sync_concurrency: int = Field(2, ge=1, le=16)
    # Test-only: allows file:// remotes. Production refuses to start with it.
    git_allow_local_sources: bool = False

    # Dynamic inventory (app.inventory_sources): a refresh runs ansible-inventory in a worker.
    inventory_refresh_timeout_seconds: int = Field(300, ge=10, le=3600)
    inventory_max_output_mb: int = Field(32, ge=1, le=256)
    inventory_max_hosts: int = Field(20_000, ge=1)
    inventory_max_groups: int = Field(5_000, ge=1)

    # Playbook checks (app.lint): ansible-lint in a worker, a few at a time across all workers.
    lint_timeout_seconds: int = Field(120, ge=10, le=600)
    lint_max_running: int = Field(2, ge=1, le=64)

    # Secret store (app.secret_store): credentials and vault passwords may live in OpenBao or
    # HashiCorp Vault (KV v2) instead of AnsiDeck's database. Off unless the URL is set. Each
    # project's secrets live under <kv mount>/<path prefix>/<project id>/; AnsiDeck reads them
    # when a run starts and never stores them. Its own login: a token file (e.g. written by an
    # Agent) or AppRole (role id here, secret id in a file); both files are re-read as they
    # change. "Vault" here would collide with Ansible Vault, hence the SECRETS_STORE_ names.
    secrets_store_url: str = ""
    secrets_store_auth: Literal["token", "approle"] = "token"
    secrets_store_token_file: str = ""
    secrets_store_role_id: str = ""
    secrets_store_secret_id_file: str = ""
    secrets_store_approle_mount: str = "approle"
    secrets_store_namespace: str = ""
    secrets_store_ca_cert: str = ""
    secrets_store_kv_mount: str = "secret"
    secrets_store_path_prefix: str = "ansideck"
    # Optional: read each project's secrets with a short-lived child token limited to this
    # store policy ("{project_id}" is replaced), so the store itself keeps projects apart.
    secrets_store_project_policy: str = ""
    secrets_store_timeout_seconds: float = Field(8.0, ge=2.0, le=10.0)
    secrets_store_label: str = "OpenBao"

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

    @field_validator("credential_encryption_key")
    @classmethod
    def _valid_fernet_keys(cls, v: str) -> str:
        keys = [key.strip() for key in v.split(",") if key.strip()]
        if not keys:
            raise ValueError("CREDENTIAL_ENCRYPTION_KEY is empty")
        for position, key in enumerate(keys, start=1):
            try:
                Fernet(key)
            except ValueError:
                # The message names the position only: a typo'd key is still mostly a secret.
                raise ValueError(
                    f"CREDENTIAL_ENCRYPTION_KEY: key {position} is not a Fernet key (44 characters "
                    "of url-safe base64)"
                ) from None
        if len(set(keys)) != len(keys):
            raise ValueError("CREDENTIAL_ENCRYPTION_KEY lists the same key twice")
        return ",".join(keys)

    @property
    def credential_encryption_keys(self) -> list[str]:
        """The current key first (it encrypts), then old ones that only decrypt (a rotation)."""
        return self.credential_encryption_key.split(",")

    @field_validator("public_url", "github_url", "github_api_url")
    @classmethod
    def _strip_trailing_slash(cls, v: str) -> str:
        return v.strip().rstrip("/")

    @property
    def git_allowlist(self) -> list[str]:
        return [e.strip() for e in self.git_allowed_private_hosts.split(",") if e.strip()]

    @property
    def notify_allowlist(self) -> list[str]:
        return [e.strip() for e in self.notify_allowed_private_hosts.split(",") if e.strip()]

    @model_validator(mode="after")
    def _validate_smtp(self) -> "Settings":
        if not self.smtp_host:
            return self
        if not self.smtp_from:
            raise ValueError("SMTP_HOST is set, so SMTP_FROM (the sender address) is required.")
        local = self.smtp_host in ("localhost", "127.0.0.1", "::1")
        if (
            self.environment.lower() == "production"
            and self.smtp_tls == "none"
            and not (local or self.smtp_host in self.notify_allowlist)
        ):
            raise ValueError(
                "ENVIRONMENT=production refuses SMTP_TLS=none to a remote server (the password "
                "and messages would cross the network in clear text)."
            )
        return self

    @model_validator(mode="after")
    def _validate_metrics(self) -> "Settings":
        if not self.metrics_token:
            return self
        if self.metrics_token in (self.worker_token, self.auth_secret_key):
            raise ValueError(
                "METRICS_TOKEN must differ from WORKER_TOKEN and AUTH_SECRET_KEY: whoever "
                "scrapes metrics must not be able to act as a worker or sign sessions."
            )
        if (
            self.environment.lower() == "production"
            and len(self.metrics_token) < MIN_WORKER_TOKEN_LENGTH
        ):
            raise ValueError(
                f"ENVIRONMENT=production requires a METRICS_TOKEN of at least "
                f"{MIN_WORKER_TOKEN_LENGTH} characters."
            )
        return self

    @property
    def secrets_store_enabled(self) -> bool:
        return bool(self.secrets_store_url)

    @model_validator(mode="after")
    def _validate_secrets_store(self) -> "Settings":
        if not self.secrets_store_url:
            return self
        url = urlsplit(self.secrets_store_url)
        if url.scheme not in ("https", "http") or not url.hostname:
            raise ValueError("SECRETS_STORE_URL must be an https:// (or http://) URL")
        local = url.hostname in ("localhost", "127.0.0.1", "::1")
        if self.environment.lower() == "production" and url.scheme != "https" and not local:
            raise ValueError(
                "ENVIRONMENT=production requires https for SECRETS_STORE_URL (set "
                "SECRETS_STORE_CA_CERT for a private CA)."
            )
        segment = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")
        for name in ("secrets_store_kv_mount", "secrets_store_path_prefix",
                     "secrets_store_approle_mount"):  # fmt: skip
            if not segment.match(getattr(self, name)):
                raise ValueError(f"{name.upper()} must be one path segment (letters, digits, ._-)")
        if self.secrets_store_namespace and not all(
            segment.match(part) for part in self.secrets_store_namespace.split("/")
        ):
            raise ValueError("SECRETS_STORE_NAMESPACE has invalid characters")
        if self.secrets_store_auth == "token":
            files = {"SECRETS_STORE_TOKEN_FILE": self.secrets_store_token_file}
        else:
            if not self.secrets_store_role_id:
                raise ValueError("SECRETS_STORE_AUTH=approle needs SECRETS_STORE_ROLE_ID")
            files = {"SECRETS_STORE_SECRET_ID_FILE": self.secrets_store_secret_id_file}
        if self.secrets_store_ca_cert:
            files["SECRETS_STORE_CA_CERT"] = self.secrets_store_ca_cert
        for name, path in files.items():
            if not path:
                raise ValueError(f"the secret store needs {name}")
            if not os.access(path, os.R_OK):
                raise ValueError(f"{name} ({path}) is not a readable file")
        policy = self.secrets_store_project_policy
        if policy and (
            "{project_id}" not in policy
            or not re.fullmatch(r"[A-Za-z0-9_.{}-]{1,120}", policy)
            or policy.replace("{project_id}", "").count("{")
        ):
            raise ValueError(
                "SECRETS_STORE_PROJECT_POLICY must be a policy name containing {project_id}"
            )
        return self

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id and self.oidc_client_secret)

    @property
    def github_enabled(self) -> bool:
        return bool(self.github_client_id and self.github_client_secret)

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
    def _validate_github(self) -> "Settings":
        configured = [self.github_client_id, self.github_client_secret]
        if any(configured) and not all(configured):
            raise ValueError(
                "GitHub sign-in is partially configured: set GITHUB_CLIENT_ID and "
                "GITHUB_CLIENT_SECRET together (or neither)."
            )
        if not self.github_enabled:
            return self
        if not self.public_url.startswith(("http://", "https://")):
            raise ValueError("GitHub sign-in needs PUBLIC_URL (e.g. https://ansideck.example.com).")
        if self.environment.lower() == "production" and not all(
            url.startswith("https://")
            for url in (self.public_url, self.github_url, self.github_api_url)
        ):
            raise ValueError(
                "ENVIRONMENT=production requires https for PUBLIC_URL, GITHUB_URL and "
                "GITHUB_API_URL."
            )
        return self

    @model_validator(mode="after")
    def _refuse_shared_secrets(self) -> "Settings":
        if self.auth_secret_key == self.worker_token:
            raise ValueError(
                "AUTH_SECRET_KEY must differ from WORKER_TOKEN: workers (and so playbooks) see "
                "WORKER_TOKEN, and AUTH_SECRET_KEY signs every session."
            )
        return self

    @model_validator(mode="after")
    def _refuse_insecure_defaults_in_production(self) -> "Settings":
        if self.environment.lower() == "production":
            insecure = []
            if (
                self.auth_secret_key == _DEFAULT_AUTH_SECRET_KEY
                or is_placeholder(self.auth_secret_key)
                or len(self.auth_secret_key) < MIN_AUTH_SECRET_KEY_LENGTH
            ):
                insecure.append(
                    f"AUTH_SECRET_KEY (at least {MIN_AUTH_SECRET_KEY_LENGTH} characters)"
                )
            if self.admin_password == _DEFAULT_ADMIN_PASSWORD or is_placeholder(
                self.admin_password
            ):
                insecure.append("ADMIN_PASSWORD")
            db_password = make_url(self.database_url).password or ""
            if db_password == _DEFAULT_DB_PASSWORD or is_placeholder(db_password):
                insecure.append("the database password (POSTGRES_PASSWORD / DATABASE_URL)")
            if (
                self.worker_token == DEFAULT_WORKER_TOKEN
                or is_placeholder(self.worker_token)
                or len(self.worker_token) < MIN_WORKER_TOKEN_LENGTH
            ):
                insecure.append(f"WORKER_TOKEN (at least {MIN_WORKER_TOKEN_LENGTH} characters)")
            if is_placeholder(self.metrics_token):
                insecure.append("METRICS_TOKEN")
            if self.git_allow_local_sources:
                raise ValueError(
                    "ENVIRONMENT=production refuses GIT_ALLOW_LOCAL_SOURCES (test-only: it lets "
                    "git sources read the server's own files)."
                )
            if insecure:
                raise ValueError(
                    f"ENVIRONMENT=production but {', '.join(insecure)} still has its insecure "
                    "default. Set a real value."
                )
            if self.credential_encryption_keys[0] == EXAMPLE_CREDENTIAL_ENCRYPTION_KEY:
                raise ValueError(
                    "ENVIRONMENT=production refuses the example CREDENTIAL_ENCRYPTION_KEY from "
                    '.env.example: anyone can decrypt with it. Generate a key (python -c "from '
                    'cryptography.fernet import Fernet; print(Fernet.generate_key().decode())") '
                    "and put it first, keeping the example key after a comma "
                    "(CREDENTIAL_ENCRYPTION_KEY=<new key>,<example key>); start AnsiDeck, run "
                    "`python -m app.cli reencrypt-secrets` in the backend container, then remove "
                    "the example key. See docs/upgrading.md."
                )
        return self


# Docker secrets (or any directory of files): a file named after a setting, such as
# /run/secrets/credential_encryption_key, provides its value when the environment doesn't. Only the
# API reads these; workers take WORKER_TOKEN from their environment, which they then scrub, because
# compose makes secret files readable to every user in a container, playbook runs included.
DEFAULT_SECRETS_DIR = "/run/secrets"


@lru_cache
def get_settings() -> Settings:
    secrets_dir = os.environ.get("SECRETS_DIR", DEFAULT_SECRETS_DIR)
    return Settings(_secrets_dir=secrets_dir if os.path.isdir(secrets_dir) else None)
