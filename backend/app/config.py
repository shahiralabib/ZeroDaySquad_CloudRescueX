from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url

# Bearer-token lifetime in minutes. The single source of truth for the settings validation below and for app/auth.py.
AUTH_TOKEN_TTL_DEFAULT_MINUTES = 60
AUTH_TOKEN_TTL_MIN_MINUTES = 5
AUTH_TOKEN_TTL_MAX_MINUTES = 720


class Settings(BaseSettings):
    app_name: str = "CloudRescue X"
    environment: str = "local"
    operating_mode: str = "DEMO"
    database_url: str = "sqlite+aiosqlite:///./cloudrescue.db"
    frontend_origins: str = Field(default="http://localhost:5173,http://127.0.0.1:5173")
    log_level: str = "INFO"
    seed_demo_data: bool = True
    monitoring_enabled: bool = True
    monitoring_default_interval_seconds: int = 30
    demo_admin_token: str = "local-demo-admin"
    # Authentication (see app/auth.py). Both values are secrets. They are validated when first used rather than here, so
    # a missing or invalid value makes protected routes answer 503 instead of stopping the application at import.
    auth_secret: SecretStr = SecretStr("")
    auth_users_json: SecretStr = SecretStr("")
    auth_token_ttl_minutes: int = Field(
        default=AUTH_TOKEN_TTL_DEFAULT_MINUTES, ge=AUTH_TOKEN_TTL_MIN_MINUTES, le=AUTH_TOKEN_TTL_MAX_MINUTES
    )
    ai_provider: str = "local"
    gemini_api_key: str = ""
    gemini_model: str = ""
    ai_confidence_threshold: float = Field(default=0.65, ge=0, le=1)
    gemini_timeout_seconds: float = Field(default=30, gt=0, le=120)
    gemini_max_retries: int = Field(default=2, ge=0, le=5)
    google_cloud_project: str = ""
    google_cloud_location: str = "global"
    cloud_monitoring_enabled: bool = False
    cloud_logging_enabled: bool = False
    firestore_enabled: bool = False
    storage_backend: str = "sqlite"
    firestore_database: str = "(default)"
    request_max_body_bytes: int = Field(default=1048576, ge=1024, le=10485760)
    rate_limit_per_minute: int = Field(default=120, ge=1, le=10000)
    recovery_approval_expiry_minutes: int = Field(default=15, ge=1, le=1440)

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.frontend_origins.split(",") if origin.strip()]

    @property
    def database_file(self) -> Path | None:
        """Absolute SQLite file path (relative URLs resolve against the working directory), else None."""
        url = make_url(self.database_url)
        if url.get_backend_name() != "sqlite" or url.database in (None, "", ":memory:"):
            return None
        return Path(url.database).expanduser().resolve()

    @property
    def database_description(self) -> str:
        """Human-readable database location for logs. Passwords are masked for non-SQLite URLs."""
        url = make_url(self.database_url)
        if url.get_backend_name() == "sqlite":
            database_file = self.database_file
            return f"sqlite file {database_file}" if database_file else "sqlite in-memory"
        return url.render_as_string(hide_password=True)

    @property
    def database_label(self) -> str:
        """Short, non-sensitive database identifier for API responses (no directory path, no credentials)."""
        backend = make_url(self.database_url).get_backend_name()
        if backend != "sqlite":
            return backend
        database_file = self.database_file
        return database_file.name if database_file else "sqlite in-memory"

    @property
    def demo_mode(self) -> bool:
        return self.operating_mode.upper() != "LIVE"

    @property
    def data_source(self) -> str:
        return "local_simulation" if self.demo_mode else "external_integrations"


@lru_cache
def get_settings() -> Settings:
    return Settings()
