"""Administrator views and protected account/file mutations."""

from __future__ import annotations

import platform

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import func, or_

from ..auth_service import AuthenticationError, find_user, get_auth_service
from ..decorators import admin_required
from ..extensions import db
from ..models import ActivityLog, EncryptedFile, SharedFile, User, utcnow
from ..storage_service import StorageBackendError, delete_storage
from .common import audit_action


def _final_active_admin(target: User) -> bool:
    return target.is_admin and target.is_active and User.query.filter_by(role="admin", is_active=True).count() <= 1


def _page(query, *, per_page: int = 25):  # type: ignore[no-untyped-def]
    page = max(request.args.get("page", 1, type=int), 1)
    return query.paginate(page=page, per_page=per_page, error_out=False)


def register_admin_routes(app: Flask) -> None:
    @app.get("/admin", endpoint="admin_dashboard")
    @admin_required
    def admin_dashboard():  # type: ignore[no-untyped-def]
        total_users = User.query.count()
        total_files = EncryptedFile.query.count()
        total_activities = ActivityLog.query.count()
        stats = {"active_users": User.query.filter_by(is_active=True).count()}
        recent_users = User.query.order_by(User.created_at.desc()).limit(8).all()
        recent_activity = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(12).all()
        return render_template(
            "admin/dashboard.html", stats=stats, total_users=total_users, total_files=total_files,
            total_activities=total_activities,
            recent_users=recent_users, recent_activity=recent_activity,
        )

    @app.get("/admin/users", endpoint="admin_users")
    @admin_required
    def admin_users():  # type: ignore[no-untyped-def]
        query = User.query
        search = request.args.get("q", "").strip()
        if search:
            pattern = f"%{search}%"
            query = query.filter(or_(User.username.ilike(pattern), User.email.ilike(pattern), User.full_name.ilike(pattern)))
        users = _page(query.order_by(User.created_at.desc()))
        return render_template("admin/users.html", users=users, search=search, total_users=User.query.count())

    @app.route("/admin/users/create", methods=["GET", "POST"], endpoint="admin_create_user")
    @admin_required
    def admin_create_user():  # type: ignore[no-untyped-def]
        if request.method == "POST":
            data = request.form
            email, username, password = data.get("email", "").strip().lower(), data.get("username", "").strip(), data.get("password", "")
            if not email or not username or len(password) < 8 or find_user(email) or find_user(username):
                flash("Provide a unique email/username and a password of at least 8 characters.", "error")
            else:
                try:
                    user = get_auth_service().register(
                        email=email, username=username, password=password,
                        full_name=data.get("full_name", "").strip() or username,
                    )
                    if data.get("is_admin"):
                        user.role = "admin"
                        db.session.commit()
                    audit_action("admin.user_created", details={"role": user.role}, target_type="user", target_id=user.id)
                    flash("User created.", "success")
                    return redirect(url_for("admin_users"))
                except (AuthenticationError, RuntimeError) as exc:
                    db.session.rollback()
                    flash(str(exc), "error")
        return render_template("admin/create_user.html")

    @app.post("/admin/users/<int:user_id>/delete", endpoint="admin_delete_user")
    @admin_required
    def admin_delete_user(user_id: int):  # type: ignore[no-untyped-def]
        target = db.session.get(User, user_id)
        if not target:
            abort(404)
        if target.id == current_user.id:
            return jsonify(success=False, message="You cannot delete your own account."), 400
        if _final_active_admin(target):
            return jsonify(success=False, message="The final active administrator cannot be removed."), 400
        target_id, target_email = target.id, target.email
        storage_names = [item.storage_name for item in target.encrypted_files]
        try:
            get_auth_service().delete_user(target)
            User.query.filter_by(id=target_id).delete(synchronize_session=False)
            db.session.commit()
        except AuthenticationError as exc:
            db.session.rollback()
            return jsonify(success=False, message=str(exc)), 503
        for storage_name in storage_names:
            try:
                delete_storage("vault", storage_name)
            except StorageBackendError:
                app.logger.warning("Could not remove user vault object %s", storage_name)
        audit_action("admin.user_deleted", details={"email": target_email}, target_type="user", target_id=target_id)
        return jsonify(success=True, message="User and Supabase identity deleted.")

    @app.post("/admin/users/<int:user_id>/toggle_admin", endpoint="admin_toggle_user_admin")
    @admin_required
    def admin_toggle_user_admin(user_id: int):  # type: ignore[no-untyped-def]
        target = db.session.get(User, user_id)
        if not target:
            abort(404)
        if target.id == current_user.id and target.is_admin:
            return jsonify(success=False, message="You cannot remove your own administrator role."), 400
        if _final_active_admin(target):
            return jsonify(success=False, message="The final active administrator cannot be demoted."), 400
        target.role = "user" if target.is_admin else "admin"
        target.session_version += 1
        audit_action("admin.role_changed", details={"role": target.role}, target_type="user", target_id=target.id, commit=False)
        db.session.commit()
        return jsonify(success=True, role=target.role, is_admin=target.is_admin)

    @app.post("/admin/users/<int:user_id>/toggle_active", endpoint="admin_toggle_user_active")
    @admin_required
    def admin_toggle_user_active(user_id: int):  # type: ignore[no-untyped-def]
        target = db.session.get(User, user_id)
        if not target:
            abort(404)
        if target.id == current_user.id:
            return jsonify(success=False, message="You cannot disable your own account."), 400
        if _final_active_admin(target):
            return jsonify(success=False, message="The final active administrator cannot be disabled."), 400
        target.is_active = not target.is_active
        target.session_version += 1
        audit_action("admin.active_changed", details={"active": target.is_active}, target_type="user", target_id=target.id, commit=False)
        db.session.commit()
        return jsonify(success=True, active=target.is_active)

    @app.get("/admin/files", endpoint="admin_files")
    @admin_required
    def admin_files():  # type: ignore[no-untyped-def]
        files = _page(EncryptedFile.query.order_by(EncryptedFile.created_at.desc()))
        total_size = db.session.query(func.coalesce(func.sum(EncryptedFile.file_size), 0)).scalar()
        return render_template("admin/files.html", files=files, total_files=EncryptedFile.query.count(), total_size=total_size)

    @app.post("/admin/files/<int:file_id>/delete", endpoint="admin_delete_file")
    @admin_required
    def admin_delete_file(file_id: int):  # type: ignore[no-untyped-def]
        record = db.session.get(EncryptedFile, file_id)
        if not record:
            abort(404)
        storage_name = record.storage_name
        audit_action("admin.file_deleted", details={"owner_id": record.user_id}, target_type="encrypted_file", target_id=record.id, commit=False)
        db.session.delete(record)
        db.session.commit()
        try:
            delete_storage("vault", storage_name)
        except StorageBackendError:
            app.logger.warning("Could not remove admin-deleted vault object %s", storage_name)
        return jsonify(success=True)

    @app.get("/admin/activity", endpoint="admin_activity")
    @admin_required
    def admin_activity():  # type: ignore[no-untyped-def]
        activities = _page(ActivityLog.query.order_by(ActivityLog.timestamp.desc()), per_page=40)
        top_rows = db.session.query(User, func.count(ActivityLog.id)).join(ActivityLog, ActivityLog.user_id == User.id).group_by(User.id).order_by(func.count(ActivityLog.id).desc()).limit(8).all()
        top_users = []
        for user, count in top_rows:
            user.activity_count = count
            top_users.append(user)
        start_of_today = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        stats = {"total": ActivityLog.query.count(), "failed": ActivityLog.query.filter_by(success=False).count()}
        today_activities = ActivityLog.query.filter(ActivityLog.timestamp >= start_of_today).count()
        return render_template(
            "admin/activity.html", activities=activities, top_users=top_users, stats=stats,
            total_activities=stats["total"], today_activities=today_activities,
        )

    @app.get("/admin/settings", endpoint="admin_settings")
    @admin_required
    def admin_settings():  # type: ignore[no-untyped-def]
        db_stats = {"users": User.query.count(), "files": EncryptedFile.query.count(), "activities": ActivityLog.query.count(), "shared_files": SharedFile.query.count()}
        system_info = {
            "platform": platform.system(), "platform_release": platform.version(), "hostname": platform.node(),
            "architecture": platform.machine(), "python": platform.python_version(), "ram": "Not collected",
        }
        return render_template("admin/settings.html", settings={"operational": True}, db_stats=db_stats, system_info=system_info)
