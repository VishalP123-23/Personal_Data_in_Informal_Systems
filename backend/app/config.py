import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "postgresql+psycopg://clinic_app:CHANGE_ME@127.0.0.1:5432/clinic_privacy")
    app_env: str = os.getenv("APP_ENV", "local-demo")
    secret_key: str = os.getenv("SECRET_KEY", "local-demo-only-change-this-secret")
    cookie_secure: bool = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    session_ttl_hours: int = int(os.getenv("SESSION_TTL_HOURS", "8"))
    allowed_origin: str = os.getenv("ALLOWED_ORIGIN", "http://127.0.0.1:5173")

settings = Settings()
