"""Signed-in profile and Supabase credential settings."""

from __future__ import annotations

from io import BytesIO
import secrets
from uuid import UUID
import warnings

from flask import (
    Flask,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_login import current_user, login_required, logout_user
from PIL import Image, ImageOps, UnidentifiedImageError
from sqlalchemy.exc import SQLAlchemyError

from ..auth_service import AuthenticationError, get_auth_service
from ..extensions import db
from ..forms import AvatarUploadForm, ChangePasswordForm
from ..storage_service import StorageBackendError, delete_storage, read_bytes, store_bytes
from .common import audit_action


ALLOWED_AVATAR_FORMATS = {"JPEG", "PNG", "WEBP"}
MAX_AVATAR_PIXELS = 40_000_000
AVATAR_DIMENSIONS = (512, 512)


class AvatarImageError(ValueError):
    """A safe avatar-processing error that can be shown to the user."""


def _remove_avatar_file(filename: str | None) -> None:
    delete_storage("avatars", filename)


def _normalized_avatar(payload: bytes) -> bytes:
    if not payload:
        raise AvatarImageError("Choose a PNG, JPEG, or WebP profile photo.")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(payload)) as probe:
                if probe.format not in ALLOWED_AVATAR_FORMATS:
                    raise AvatarImageError("Use a PNG, JPEG, or WebP profile photo.")
                width, height = probe.size
                if width < 1 or height < 1 or width * height > MAX_AVATAR_PIXELS:
                    raise AvatarImageError("That image is too large to process safely.")
                probe.verify()

            with Image.open(BytesIO(payload)) as source:
                source.seek(0)
                source.load()
                oriented = ImageOps.exif_transpose(source)
                has_alpha = "A" in oriented.getbands() or "transparency" in oriented.info
                normalized = oriented.convert("RGBA" if has_alpha else "RGB")
                width, height = normalized.size
                side = min(width, height)
                left = (width - side) // 2
                top = (height - side) // 2
                avatar = normalized.crop((left, top, left + side, top + side))
                avatar.thumbnail(AVATAR_DIMENSIONS, Image.Resampling.LANCZOS)
                output = BytesIO()
                avatar.save(
                    output,
                    format="WEBP",
                    quality=88,
                    method=6,
                    exif=b"",
                    icc_profile=b"",
                    xmp=b"",
                )
                return output.getvalue()
    except AvatarImageError:
        raise
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        UnidentifiedImageError,
        OSError,
        SyntaxError,
        ValueError,
    ) as exc:
        raise AvatarImageError("That image could not be read. Try another file.") from exc


def _store_avatar(payload: bytes) -> None:
    try:
        subject = UUID(str(current_user.auth_subject)).hex
    except (AttributeError, TypeError, ValueError) as exc:
        raise AvatarImageError("This account cannot store a profile photo yet.") from exc

    filename = f"{subject}-{secrets.token_hex(8)}.webp"
    old_filename = current_user.avatar_filename
    try:
        store_bytes("avatars", filename, payload, content_type="image/webp")
        current_user.avatar_filename = filename
        db.session.commit()
    except (StorageBackendError, SQLAlchemyError) as exc:
        db.session.rollback()
        try:
            delete_storage("avatars", filename)
        except StorageBackendError:
            current_app.logger.warning("Could not remove rolled-back avatar object")
        raise AvatarImageError("The profile photo could not be stored.") from exc

    try:
        _remove_avatar_file(old_filename)
    except StorageBackendError:
        current_app.logger.warning("Could not remove replaced avatar %s", old_filename)


def register_profile_routes(app: Flask) -> None:
    @app.get("/profile/avatar", endpoint="profile_avatar")
    @login_required
    def profile_avatar():  # type: ignore[no-untyped-def]
        try:
            payload = read_bytes("avatars", current_user.avatar_filename or "")
        except (ValueError, FileNotFoundError):
            abort(404)
        except StorageBackendError:
            current_app.logger.exception("Profile photo storage is unavailable")
            abort(503)
        response = send_file(
            BytesIO(payload),
            mimetype="image/webp",
            conditional=True,
            etag=True,
            max_age=0,
        )
        response.headers["Cache-Control"] = "private, no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.route("/profile", methods=["GET", "POST"], endpoint="profile")
    @login_required
    def profile():  # type: ignore[no-untyped-def]
        password_form = ChangePasswordForm()
        avatar_form = AvatarUploadForm()
        if request.method == "POST":
            action = request.form.get("action", "")
            if action == "change_password" and password_form.validate_on_submit():
                try:
                    get_auth_service().change_password(
                        current_user,
                        password_form.current_password.data,
                        password_form.new_password.data,
                    )
                    audit_action("profile.password_changed")
                    logout_user()
                    session.clear()
                    flash("Password changed. Sign in again on this device.", "success")
                    return redirect(url_for("login"))
                except AuthenticationError as exc:
                    flash(str(exc), "error")
            elif action == "update_profile":
                full_name = request.form.get("full_name", "").strip()
                if 2 <= len(full_name) <= 120:
                    current_user.full_name = full_name
                    db.session.commit()
                    audit_action("profile.updated")
                    flash("Profile updated.", "success")
                    return redirect(url_for("profile"))
                flash("Enter a valid full name.", "error")
            elif action in {"upload_avatar", "update_avatar"}:
                if avatar_form.validate_on_submit():
                    upload = avatar_form.avatar.data
                    payload = upload.stream.read(current_app.config["AVATAR_MAX_BYTES"] + 1)
                    if len(payload) > current_app.config["AVATAR_MAX_BYTES"]:
                        maximum_mb = max(1, current_app.config["AVATAR_MAX_BYTES"] // (1024 * 1024))
                        error = f"Profile photos must be {maximum_mb} MB or smaller."
                    else:
                        try:
                            _store_avatar(_normalized_avatar(payload))
                            audit_action("profile.avatar_updated")
                            flash("Profile photo updated.", "success")
                            return redirect(url_for("profile"))
                        except AvatarImageError as exc:
                            error = str(exc)
                else:
                    error = next(
                        (
                            message
                            for messages in avatar_form.errors.values()
                            for message in messages
                        ),
                        "Choose a PNG, JPEG, or WebP profile photo.",
                    )
                if error not in avatar_form.avatar.errors:
                    avatar_form.avatar.errors = [*avatar_form.avatar.errors, error]
                audit_action(
                    "profile.avatar_update_failed",
                    details={"reason": "validation"},
                    success=False,
                )
                flash(error, "error")
            elif action == "remove_avatar":
                old_filename = current_user.avatar_filename
                if old_filename:
                    current_user.avatar_filename = None
                    try:
                        db.session.commit()
                    except SQLAlchemyError:
                        db.session.rollback()
                        flash("The profile photo could not be removed.", "error")
                    else:
                        try:
                            _remove_avatar_file(old_filename)
                        except StorageBackendError:
                            current_app.logger.warning(
                                "Could not remove avatar file %s", old_filename
                            )
                        audit_action("profile.avatar_removed")
                        flash("Profile photo removed.", "success")
                        return redirect(url_for("profile"))
                else:
                    flash("There is no profile photo to remove.", "warning")
        return render_template(
            "profile.html",
            password_form=password_form,
            avatar_form=avatar_form,
        )

    @app.post("/profile/avatar", endpoint="update_avatar")
    @login_required
    def update_avatar():  # type: ignore[no-untyped-def]
        """Accept the profile form's avatar actions at the private avatar URL."""
        return profile()
