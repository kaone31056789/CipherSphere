"""Registration, login, logout, and password recovery routes."""

from __future__ import annotations

import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from flask import Flask, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_user, logout_user
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError

from ..auth_service import AuthenticationError, get_auth_service
from ..extensions import db
from ..forms import ForgotPasswordForm, LoginForm, RegisterForm, ResetPasswordForm
from ..models import User, utcnow
from ..security import rate_limit
from .common import audit_action


def _safe_next(target: str | None) -> bool:
    if not target or not target.startswith("/") or target.startswith("//"):
        return False
    if "\\" in target or any(ord(character) < 32 for character in target):
        return False
    candidate = urlsplit(target)
    return not candidate.scheme and not candidate.netloc


def _oauth_callback_url(base_url: str, flow: str) -> str:
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError("SUPABASE_OAUTH_REDIRECT_URL must be an absolute HTTP(S) URL.")
    query = [(key, value) for key, value in parse_qsl(parsed.query) if key != "flow"]
    query.append(("flow", flow))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def _audit_oauth_failure(action: str, details: dict[str, str]) -> None:
    """Record an OAuth failure without replacing the user-facing auth error."""
    try:
        audit_action(action, details=details, success=False)
    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("Could not record OAuth failure audit")


def register_auth_routes(app: Flask) -> None:
    @app.route("/register", methods=["GET", "POST"], endpoint="register")
    @rate_limit(
        "auth.register",
        limit_config="AUTH_RATE_LIMIT_REGISTER",
        window_seconds=3600,
        methods={"POST"},
    )
    def register():  # type: ignore[no-untyped-def]
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        form = RegisterForm()
        if form.validate_on_submit():
            username = form.username.data.strip()
            email = form.email.data.strip().lower()
            if User.query.filter(func.lower(User.username) == username.lower()).first():
                form.username.errors.append("That username is already in use.")
            elif User.query.filter(func.lower(User.email) == email).first():
                form.email.errors.append("An account with that email already exists.")
            else:
                try:
                    user = get_auth_service().register(
                        username=username,
                        email=email,
                        full_name=form.full_name.data,
                        password=form.password.data,
                    )
                    audit_action("auth.register", user_id=user.id, target_type="user", target_id=user.id)
                    flash("Account created. Confirm your email, then sign in.", "success")
                    return redirect(url_for("login"))
                except (AuthenticationError, RuntimeError) as exc:
                    db.session.rollback()
                    flash(str(exc), "error")
        return render_template("register.html", form=form)

    @app.route("/login", methods=["GET", "POST"], endpoint="login")
    @rate_limit(
        "auth.login",
        limit_config="AUTH_RATE_LIMIT_LOGIN",
        window_seconds=900,
        methods={"POST"},
    )
    def login():  # type: ignore[no-untyped-def]
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        form = LoginForm()
        if form.validate_on_submit():
            try:
                user = get_auth_service().authenticate(form.username.data, form.password.data)
                user.last_login = utcnow()
                db.session.commit()
                session.clear()
                login_user(user, remember=form.remember.data)
                session["auth_session_version"] = user.session_version
                session.permanent = bool(form.remember.data)
                audit_action("auth.login", user_id=user.id)
                target = request.args.get("next")
                if _safe_next(target):
                    return redirect(target)
                return redirect(url_for("admin_dashboard" if user.is_admin else "dashboard"))
            except AuthenticationError as exc:
                audit_action("auth.login_failed", details={"identifier": form.username.data[:254]}, success=False)
                flash(str(exc), "error")
        return render_template(
            "login.html",
            form=form,
            google_auth_enabled=get_auth_service().google_provider_enabled(),
        )

    @app.get("/auth/google", endpoint="google_login")
    @rate_limit(
        "auth.google_start",
        limit_config="AUTH_RATE_LIMIT_OAUTH",
        window_seconds=300,
    )
    def google_login():  # type: ignore[no-untyped-def]
        if current_user.is_authenticated:
            return redirect(url_for("admin_dashboard" if current_user.is_admin else "dashboard"))
        target = request.args.get("next")
        safe_target = target if _safe_next(target) else None
        flow = secrets.token_urlsafe(32)
        try:
            callback_url = _oauth_callback_url(
                current_app.config["SUPABASE_OAUTH_REDIRECT_URL"], flow
            )
            authorization_url, verifier = get_auth_service().google_oauth_url(callback_url)
        except (AuthenticationError, RuntimeError) as exc:
            _audit_oauth_failure(
                "auth.oauth_start_failed",
                {"provider": "google"},
            )
            flash(str(exc), "error")
            return redirect(url_for("login"))
        session["google_oauth_flow"] = flow
        session["google_oauth_verifier"] = verifier
        session["google_oauth_redirect"] = callback_url
        session["google_oauth_next"] = safe_target
        return redirect(authorization_url)

    @app.get("/auth/callback", endpoint="auth_callback")
    @rate_limit(
        "auth.google_callback",
        limit_config="AUTH_RATE_LIMIT_OAUTH",
        window_seconds=300,
    )
    def auth_callback():  # type: ignore[no-untyped-def]
        expected_flow = str(session.pop("google_oauth_flow", "") or "")
        verifier = str(session.pop("google_oauth_verifier", "") or "")
        callback_url = str(session.pop("google_oauth_redirect", "") or "")
        target = session.pop("google_oauth_next", None)
        supplied_flow = str(request.values.get("flow", "") or "")
        provider_error = str(request.values.get("error_description", "") or "")
        auth_code = str(request.values.get("code", "") or "")

        flow_matches = bool(
            expected_flow
            and supplied_flow
            and secrets.compare_digest(expected_flow, supplied_flow)
        )
        if provider_error or not flow_matches or not auth_code or not verifier or not callback_url:
            _audit_oauth_failure(
                "auth.oauth_failed",
                {
                    "provider": "google",
                    "reason": "provider_error" if provider_error else "invalid_flow",
                },
            )
            flash("Google sign-in was cancelled or the request expired. Please try again.", "error")
            return redirect(url_for("login"))

        try:
            user = get_auth_service().complete_google_oauth(
                auth_code, verifier, callback_url
            )
            user.last_login = utcnow()
            db.session.commit()
            session.clear()
            login_user(user, remember=False)
            session["auth_session_version"] = user.session_version
            session.permanent = False
            audit_action(
                "auth.oauth_login",
                user_id=user.id,
                details={"provider": "google"},
            )
            if _safe_next(target):
                return redirect(target)
            return redirect(url_for("admin_dashboard" if user.is_admin else "dashboard"))
        except (AuthenticationError, RuntimeError) as exc:
            db.session.rollback()
            _audit_oauth_failure(
                "auth.oauth_failed",
                {"provider": "google", "reason": "code_exchange"},
            )
            flash(str(exc), "error")
            return redirect(url_for("login"))

    @app.post("/logout", endpoint="logout")
    def logout():  # type: ignore[no-untyped-def]
        if current_user.is_authenticated:
            audit_action("auth.logout")
            logout_user()
        session.clear()
        return redirect(url_for("index"))

    @app.route("/forgot_password", methods=["GET", "POST"], endpoint="forgot_password")
    @rate_limit(
        "auth.password_recovery",
        limit_config="AUTH_RATE_LIMIT_RECOVERY",
        window_seconds=3600,
        methods={"POST"},
    )
    def forgot_password():  # type: ignore[no-untyped-def]
        form = ForgotPasswordForm()
        if form.validate_on_submit():
            try:
                user = get_auth_service().request_password_reset(form.username.data)
                audit_action("auth.password_reset_requested", user_id=user.id if user else None)
            except (AuthenticationError, RuntimeError):
                pass
            flash("If that account exists, password reset instructions have been sent.", "success")
            return redirect(url_for("login"))
        return render_template("forgot_password.html", form=form)

    @app.route("/reset_password", methods=["GET", "POST"], endpoint="reset_password")
    @rate_limit(
        "auth.password_reset",
        limit_config="AUTH_RATE_LIMIT_RECOVERY",
        window_seconds=3600,
        methods={"POST"},
    )
    def reset_password():  # type: ignore[no-untyped-def]
        form = ResetPasswordForm()
        if form.validate_on_submit():
            try:
                user = get_auth_service().complete_password_recovery(
                    form.access_token.data,
                    form.refresh_token.data,
                    form.new_password.data,
                )
                audit_action("auth.password_reset_completed", user_id=user.id)
                session.clear()
                flash("Password updated. Please sign in.", "success")
                return redirect(url_for("login"))
            except AuthenticationError as exc:
                flash(str(exc), "error")
        return render_template("reset_password.html", form=form)
