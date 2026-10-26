import os
from dataclasses import dataclass, field
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")


def normalize_database_url(url: str) -> str:
    if not url:
        return url
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg://", 1)
    if url.startswith("postgresql://") and not url.startswith("postgresql+"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


raw_origins = os.getenv("ALLOWED_ORIGINS", os.getenv("ALLOWED_ORIGIN", "http://127.0.0.1:5173"))
parsed_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]


@dataclass(frozen=True)
class Settings:
    database_url: str = normalize_database_url(
        os.getenv("DATABASE_URL", "postgresql+psycopg://clinic_app:CHANGE_ME@127.0.0.1:5432/clinic_privacy")
    )
    app_env: str = os.getenv("APP_ENV", "local-demo")
    secret_key: str = os.getenv("SECRET_KEY", "local-demo-only-change-this-secret")
    cookie_secure: bool = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    cookie_samesite: str = os.getenv("COOKIE_SAMESITE", "lax")
    session_ttl_hours: int = int(os.getenv("SESSION_TTL_HOURS", "8"))
    allowed_origin: str = parsed_origins[0] if parsed_origins else "http://127.0.0.1:5173"
    allowed_origins: list[str] = field(default_factory=lambda: parsed_origins)


settings = Settings()
