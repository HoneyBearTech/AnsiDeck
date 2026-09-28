import os
import socket

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Same values as app.config, which this module must not import.
DEFAULT_WORKER_TOKEN = "change-me-dev-only-worker-token"
MIN_WORKER_TOKEN_LENGTH = 32


class WorkerSettings(BaseSettings):
    """From the environment only (no .env file: the worker must not pick up the API's)."""

    model_config = SettingsConfigDict(extra="ignore")

    environment: str = "development"
    ansideck_api_url: str = "http://backend:8001"
    worker_token: str = DEFAULT_WORKER_TOKEN
    worker_id: str = Field(default_factory=lambda: f"{socket.gethostname()}:{os.getpid()}")
    worker_slots: int = Field(1, ge=1, le=64)
    # Read-only for the worker; the API installs into it.
    galaxy_dir: str = "/data/galaxy"
    # On SIGTERM, how long running runs may finish before they are stopped.
    worker_drain_seconds: float = Field(30.0, ge=0)

    @model_validator(mode="after")
    def _refuse_default_token_in_production(self) -> "WorkerSettings":
        if self.environment.lower() == "production" and (
            self.worker_token == DEFAULT_WORKER_TOKEN
            or len(self.worker_token) < MIN_WORKER_TOKEN_LENGTH
        ):
            raise ValueError(
                "ENVIRONMENT=production but WORKER_TOKEN still has its insecure default "
                f"(set the same value, at least {MIN_WORKER_TOKEN_LENGTH} characters, on the "
                "API and the workers)."
            )
        return self
