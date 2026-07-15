"""CipherSphere Flask application factory."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import click
from dotenv import load_dotenv
from flask import Flask, session
from flask_login import current_user, logout_user
from sqlalchemy import text

load_dotenv()

from .auth_service import build_auth_service, find_user
from .encryption import EncryptionManager
from .extensions import csrf, db, login_manager
from .models import User
from .routes import register_routes
from .security import init_security_headers, validate_runtime_security
from .settings import Config


def create_app(config: dict[str, Any] | type[Config] | None = None) -> Flask:
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        instance_relative_config=False,
    )
    app.config.from_object(Config)
    if config:
        app.config.from_mapping(config) if isinstance(config, dict) else app.config.from_object(config)
    validate_runtime_security(app)
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite:"):
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = app.config.get("SQLITE_ENGINE_OPTIONS", {})

    if app.config.get("STORAGE_BACKEND", "local") == "local":
        for key in ("VAULT_FOLDER", "TEMP_FOLDER", "AVATAR_FOLDER"):
            Path(app.config[key]).mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    login_manager.login_message = "Please sign in to continue."
    login_manager.login_message_category = "warning"
    init_security_headers(app)
    app.extensions["auth_service"] = build_auth_service(app.config["AUTH_PROVIDER"])
    app.extensions["encryption_manager"] = EncryptionManager()
    if app.config.get("SCHEMA_BOOTSTRAP") and not app.config[
        "SQLALCHEMY_DATABASE_URI"
    ].startswith("sqlite:"):
        with app.app_context():
            # A transaction-scoped advisory lock makes this safe across
            # concurrent serverless cold starts. create_all only adds missing
            # tables; it does not rewrite or drop existing production data.
            with db.engine.begin() as connection:
                connection.execute(
                    text("SELECT pg_advisory_xact_lock(213546879012345678::bigint)")
                )
                db.metadata.create_all(bind=connection)
    elif app.config.get("AUTO_CREATE_DATABASE", True):
        with app.app_context():
            db.create_all()

    @login_manager.user_loader
    def load_user(user_id: str) -> User | None:
        try:
            return db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None

    @app.before_request
    def validate_login_session() -> None:
        if not current_user.is_authenticated:
            return
        expected = session.get("auth_session_version")
        if not current_user.is_active or expected != current_user.session_version:
            logout_user()
            session.clear()

    @app.template_filter("b64encode")
    def b64encode_filter(data: Any) -> str:
        raw = data if isinstance(data, bytes) else str(data).encode()
        return base64.b64encode(raw).decode()

    register_routes(app)
    register_cli(app)
    return app


def register_cli(app: Flask) -> None:
    @app.cli.command("bootstrap-admin")
    @click.option("--email", envvar="ADMIN_EMAIL")
    @click.option("--username", envvar="ADMIN_USERNAME")
    @click.option("--password", envvar="ADMIN_PASSWORD", hide_input=True)
    @click.option("--full-name", envvar="ADMIN_FULL_NAME", default="CipherSphere Administrator")
    def bootstrap_admin(email: str | None, username: str | None, password: str | None, full_name: str) -> None:
        """Create the first admin without embedding credentials in source code."""
        if not email or not username or not password:
            raise click.UsageError("Provide --email, --username and --password (or matching ADMIN_* variables).")
        if len(password) < 8:
            raise click.UsageError("Admin password must contain at least 8 characters.")
        existing = find_user(email) or find_user(username)
        if existing:
            existing.role = "admin"
            existing.is_active = True
            existing.session_version += 1
            db.session.commit()
            click.echo(f"Promoted {existing.email} to administrator.")
            return
        provider = app.extensions["auth_service"]
        user = provider.create_admin(
            email=email,
            username=username,
            password=password,
            full_name=full_name,
        )
        click.echo(f"Created administrator {user.email}.")
