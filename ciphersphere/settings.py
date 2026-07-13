"""Environment-backed application settings."""

from __future__ import annotations

import os
import secrets
from datetime import timedelta
from pathlib import Path

from sqlalchemy.pool import NullPool


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _is_production() -> bool:
    environment = os.getenv("CIPHERSPHERE_ENV", os.getenv("FLASK_ENV", "development"))
    return environment.strip().lower() == "production" or bool(os.getenv("VERCEL"))


def _bool_setting(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


def _csv_setting(name: str) -> list[str] | None:
    values = [item.strip() for item in os.getenv(name, "").split(",") if item.strip()]
    return values or None


def _secret_key() -> str:
    configured = os.getenv("SECRET_KEY", "").strip()
    if configured and configured != "replace-with-a-long-random-value":
        return configured
    if _is_production():
        # Production must use a stable secret supplied by the deployment store.
        # Runtime validation emits the actionable configuration error.
        return ""
    secret_path = PROJECT_ROOT / "instance" / ".secret_key"
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    if secret_path.exists():
        return secret_path.read_text(encoding="utf-8").strip()
    generated = secrets.token_urlsafe(64)
    secret_path.write_text(generated, encoding="utf-8")
    return generated


def _database_url() -> str:
    value = os.getenv("DATABASE_URL", "").strip()
    if not value:
        return f"sqlite:///{(PROJECT_ROOT / 'instance' / 'ciphersphere.db').as_posix()}"
    if value.startswith("postgres://"):
        return "postgresql+psycopg://" + value.removeprefix("postgres://")
    if value.startswith("postgresql://"):
        return "postgresql+psycopg://" + value.removeprefix("postgresql://")
    return value


def _path_setting(name: str, default: Path) -> str:
    value = os.getenv(name, "").strip()
    return str(Path(value).expanduser().resolve()) if value else str(default.resolve())


class Config:
    """Default configuration; secrets are supplied only through the environment."""

    VERCEL = bool(os.getenv("VERCEL"))
    PRODUCTION = _is_production()
    SECRET_KEY = _secret_key()
    SQLALCHEMY_DATABASE_URI = _database_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = (
        {
            "poolclass": NullPool,
            "connect_args": {"prepare_threshold": None},
        }
        if bool(os.getenv("VERCEL"))
        and SQLALCHEMY_DATABASE_URI.startswith("postgresql+psycopg:")
        else {
            "pool_pre_ping": True,
            **(
                {"connect_args": {"prepare_threshold": None}}
                if SQLALCHEMY_DATABASE_URI.startswith("postgresql+psycopg:")
                else {}
            ),
        }
    )
    AUTH_PROVIDER = os.getenv("AUTH_PROVIDER", "supabase").strip().lower()
    SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
    SUPABASE_ANON_KEY = (
        os.getenv("SUPABASE_PUBLISHABLE_KEY", "").strip()
        or os.getenv("SUPABASE_ANON_KEY", "").strip()
    )
    SUPABASE_SERVICE_ROLE_KEY = (
        os.getenv("SUPABASE_SECRET_KEY", "").strip()
        or os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    )
    SUPABASE_PASSWORD_REDIRECT_URL = os.getenv(
        "SUPABASE_PASSWORD_REDIRECT_URL", "http://localhost:5000/reset_password"
    )
    SUPABASE_OAUTH_REDIRECT_URL = os.getenv(
        "SUPABASE_OAUTH_REDIRECT_URL", "http://localhost:5000/auth/callback"
    )
    VAULT_FOLDER = _path_setting("VAULT_FOLDER", PROJECT_ROOT / "instance" / "vault")
    TEMP_FOLDER = _path_setting("TEMP_FOLDER", PROJECT_ROOT / "instance" / "temp")
    AVATAR_FOLDER = _path_setting("AVATAR_FOLDER", PROJECT_ROOT / "instance" / "avatars")
    AVATAR_MAX_BYTES = int(os.getenv("AVATAR_MAX_BYTES", 5 * 1024 * 1024))
    STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "local").strip().lower()
    SUPABASE_STORAGE_BUCKET = os.getenv(
        "SUPABASE_STORAGE_BUCKET", "ciphersphere-private"
    ).strip()
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 50 * 1024 * 1024))
    MAX_FORM_MEMORY_SIZE = int(os.getenv("MAX_FORM_MEMORY_SIZE", 500_000))
    MAX_FORM_PARTS = int(os.getenv("MAX_FORM_PARTS", 32))
    DOWNLOAD_TOKEN_TTL_SECONDS = int(os.getenv("DOWNLOAD_TOKEN_TTL_SECONDS", "600"))
    AUTO_CREATE_DATABASE = os.getenv(
        "AUTO_CREATE_DATABASE",
        "true" if SQLALCHEMY_DATABASE_URI.startswith("sqlite:") else "false",
    ).lower() == "true"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_NAME = "__Host-ciphersphere_session" if PRODUCTION else "session"
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = PRODUCTION or _bool_setting("SESSION_COOKIE_SECURE")
    SESSION_COOKIE_PATH = "/"
    SESSION_PROTECTION = "strong"
    SESSION_REFRESH_EACH_REQUEST = False
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_NAME = "__Host-ciphersphere_remember" if PRODUCTION else "remember_token"
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = PRODUCTION or _bool_setting("REMEMBER_COOKIE_SECURE")
    REMEMBER_COOKIE_DURATION = timedelta(days=14)
    REMEMBER_COOKIE_REFRESH_EACH_REQUEST = False
    PREFERRED_URL_SCHEME = "https" if PRODUCTION else "http"
    TRUSTED_HOSTS = _csv_setting("TRUSTED_HOSTS")
    TRUST_PROXY_HEADERS = _bool_setting("TRUST_PROXY_HEADERS")
    RATE_LIMIT_MAX_KEYS = int(os.getenv("RATE_LIMIT_MAX_KEYS", 10_000))
    AUTH_RATE_LIMIT_LOGIN = int(os.getenv("AUTH_RATE_LIMIT_LOGIN", 10))
    AUTH_RATE_LIMIT_REGISTER = int(os.getenv("AUTH_RATE_LIMIT_REGISTER", 5))
    AUTH_RATE_LIMIT_RECOVERY = int(os.getenv("AUTH_RATE_LIMIT_RECOVERY", 5))
    AUTH_RATE_LIMIT_OAUTH = int(os.getenv("AUTH_RATE_LIMIT_OAUTH", 20))
    WTF_CSRF_TIME_LIMIT = 3600
    WTF_CSRF_SSL_STRICT = PRODUCTION
