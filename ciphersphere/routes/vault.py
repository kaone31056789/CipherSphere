"""Owner-scoped encrypted vault operations."""

from __future__ import annotations

from flask import Flask, abort, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..extensions import db
from ..models import EncryptedFile
from ..storage_service import StorageBackendError, delete_storage
from .common import audit_action, issue_download


def _owned_file(file_id: int) -> EncryptedFile:
    record = db.session.get(EncryptedFile, file_id)
    if not record or record.user_id != current_user.id:
        abort(404)
    return record


def register_vault_routes(app: Flask) -> None:
    @app.get("/vault", endpoint="vault")
    @login_required
    def vault():  # type: ignore[no-untyped-def]
        files = EncryptedFile.query.filter_by(user_id=current_user.id).order_by(EncryptedFile.created_at.desc()).all()
        return render_template("vault.html", files=files, vault_files=files)

    def issue_file_download(file_id: int):  # type: ignore[no-untyped-def]
        record = _owned_file(file_id)
        try:
            _, location = issue_download("vault", record.storage_name, record.filename, current_user.id)
        except (ValueError, FileNotFoundError):
            abort(404)
        except StorageBackendError:
            app.logger.exception("Vault storage is unavailable")
            abort(503)
        audit_action("vault.download_requested", target_type="encrypted_file", target_id=record.id)
        return redirect(location)

    app.add_url_rule("/vault/download/<int:file_id>", endpoint="download_file", view_func=login_required(issue_file_download), methods=["GET"])

    @app.post("/vault/delete/<int:file_id>", endpoint="delete_file")
    @login_required
    def delete_file(file_id: int):  # type: ignore[no-untyped-def]
        record = _owned_file(file_id)
        storage_name = record.storage_name
        db.session.delete(record)
        audit_action("vault.delete", target_type="encrypted_file", target_id=record.id, commit=False)
        db.session.commit()
        try:
            delete_storage("vault", storage_name)
        except StorageBackendError:
            app.logger.warning("Could not remove deleted vault object %s", storage_name)
        if request.is_json:
            return jsonify(success=True)
        return redirect(url_for("vault"))
