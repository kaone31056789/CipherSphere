"""Public landing page and signed-in dashboard."""

from __future__ import annotations

from flask import Flask, redirect, render_template, url_for
from flask_login import current_user, login_required

from ..extensions import db
from ..models import ActivityLog, EncryptedFile, SharedFile, utcnow


def register_core_routes(app: Flask) -> None:
    @app.errorhandler(403)
    def forbidden(_error):  # type: ignore[no-untyped-def]
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(_error):  # type: ignore[no-untyped-def]
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_error(_error):  # type: ignore[no-untyped-def]
        db.session.rollback()
        return render_template("errors/500.html"), 500

    @app.get("/", endpoint="index")
    def index():  # type: ignore[no-untyped-def]
        return redirect(url_for("dashboard")) if current_user.is_authenticated else render_template("index.html")

    @app.get("/dashboard", endpoint="dashboard")
    @login_required
    def dashboard():  # type: ignore[no-untyped-def]
        recent_activity = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.timestamp.desc()).limit(10).all()
        recent_files = EncryptedFile.query.filter_by(user_id=current_user.id).order_by(EncryptedFile.created_at.desc()).limit(5).all()
        all_files = EncryptedFile.query.filter_by(user_id=current_user.id)
        stats = {
            "vault_files": all_files.count(),
            "shared_files": SharedFile.query.filter_by(shared_with_user_id=current_user.id, is_active=True).count(),
            "recent_activity": len(recent_activity),
        }
        return render_template(
            "dashboard.html",
            recent_activity=recent_activity,
            recent_files=recent_files,
            stats=stats,
            now=utcnow(),
        )
