import os
import socket

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.run_isolation import MAX_SLOTS
from app.worker.egress import Network, parse_networks

# Same values as app.config, which this module must not import.
DEFAULT_WORKER_TOKEN = "change-me-dev-only-worker-token"  # noqa: S105 - dev default, refused in production
MIN_WORKER_TOKEN_LENGTH = 32


class WorkerSettings(BaseSettings):
    """From the environment only (no .env file: the worker must not pick up the API's)."""

    model_config = SettingsConfigDict(extra="ignore", hide_input_in_errors=True)

    environment: str = "development"
    ansideck_api_url: str = "http://backend:8001"
    worker_token: str = DEFAULT_WORKER_TOKEN
    worker_id: str = Field(default_factory=lambda: f"{socket.gethostname()}:{os.getpid()}")
    worker_slots: int = Field(1, ge=1, le=MAX_SLOTS)  # one run user per slot
    # Read-only for the worker; the API installs into it.
    galaxy_dir: str = "/data/galaxy"
    # On SIGTERM, how long running runs may finish before they are stopped.
    worker_drain_seconds: float = Field(30.0, ge=0)
    # Runs can't reach the API or cloud metadata (app.worker.egress). Turning the filter off
    # is for workers whose network is restricted some other way.
    worker_egress_filter: bool = True
    # For playbooks that use the host's cloud identity (instance profile, managed identity).
    worker_allow_cloud_metadata: bool = False
    # More addresses or networks runs must not reach, comma-separated (e.g. a pod network).
    worker_blocked_networks: str = ""

    @field_validator("worker_blocked_networks")
    @classmethod
    def _valid_networks(cls, value: str) -> str:
        parse_networks(value)
        return value

    @property
    def blocked_networks(self) -> list[Network]:
        return parse_networks(self.worker_blocked_networks)

    @model_validator(mode="after")
    def _refuse_default_token_in_production(self) -> "WorkerSettings":
        if self.environment.lower() == "production" and (
            self.worker_token == DEFAULT_WORKER_TOKEN
            or self.worker_token.strip().lower().startswith("change-me")  # from .env.example
            or len(self.worker_token) < MIN_WORKER_TOKEN_LENGTH
        ):
            raise ValueError(
                "ENVIRONMENT=production but WORKER_TOKEN still has its insecure default "
                f"(set the same value, at least {MIN_WORKER_TOKEN_LENGTH} characters, on the "
                "API and the workers)."
            )
        return self
