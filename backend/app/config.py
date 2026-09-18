from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    auth_secret_key: str = "change-me-dev-only-insecure-secret"
    admin_username: str = "admin"
    admin_password: str = "admin"
    cors_origins: list[str] = ["http://localhost:5173"]
    cookie_secure: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
