"""Encrypted-file sharing with explicit sender/recipient authorization."""

from __future__ import annotations

from datetime import timedelta

from flask import Flask, abort, jsonify, redirect, render_template, request
from flask_login import current_user, login_required

from ..auth_service import find_user
from ..extensions import db
from ..models import EncryptedFile, SharedFile, utcnow
from ..storage_service import StorageBackendError
from .common import audit_action, issue_download


def _active(share: SharedFile) -> bool:
    return share.is_active and (share.expires_at is None or share.expires_at >= utcnow())


def _create_share(record: EncryptedFile, payload: dict[str, object]) -> SharedFile:
    identifier = str(payload.get("recipient") or payload.get("recipient_username") or payload.get("email") or "")
    recipient = find_user(identifier)
    if not recipient or not recipient.is_active:
        raise ValueError("Recipient was not found.")
    if recipient.id == current_user.id:
        raise ValueError("You cannot share a file with yourself.")
    permissions = "download"
    try:
        days = max(1, min(int(payload.get("expires_days") or 7), 365))
    except (TypeError, ValueError):
        days = 7
    share = SharedFile.query.filter_by(
        encrypted_file_id=record.id,
        shared_by_user_id=current_user.id,
        shared_with_user_id=recipient.id,
    ).first()
    if not share:
        share = SharedFile(
            encrypted_file_id=record.id,
            shared_by_user_id=current_user.id,
            shared_with_user_id=recipient.id,
        )
        db.session.add(share)
    share.permissions = permissions
    share.message = str(payload.get("message") or "")[:1000] or None
    share.expires_at = utcnow() + timedelta(days=days)
    share.is_active = True
    db.session.commit()
    audit_action("share.created", details={"recipient_id": recipient.id, "permissions": permissions}, target_type="encrypted_file", target_id=record.id)
    return share


def register_sharing_routes(app: Flask) -> None:
    @app.post("/vault/share/<int:file_id>", endpoint="share_file")
    @login_required
    def share_file(file_id: int):  # type: ignore[no-untyped-def]
        record = db.session.get(EncryptedFile, file_id)
        if not record or record.user_id != current_user.id:
            abort(404)
        payload = request.get_json(silent=True) or request.form.to_dict()
        try:
            share = _create_share(record, payload)
            return jsonify(success=True, share_id=share.id)
        except ValueError as exc:
            return jsonify(success=False, message=str(exc), error=str(exc)), 400

    @app.get("/shared_files", endpoint="shared_files")
    @login_required
    def shared_files():  # type: ignore[no-untyped-def]
        received = SharedFile.query.filter_by(shared_with_user_id=current_user.id).order_by(SharedFile.shared_at.desc()).all()
        sent = SharedFile.query.filter_by(shared_by_user_id=current_user.id).order_by(SharedFile.shared_at.desc()).all()
        return render_template(
            "shared_files.html", shared_files=received, sent_files=sent,
            received=received, sent=sent, now=utcnow(),
        )

    @app.get("/download_shared/<int:share_id>", endpoint="download_shared")
    @login_required
    def download_shared(share_id: int):  # type: ignore[no-untyped-def]
        share = db.session.get(SharedFile, share_id)
        if not share or share.shared_with_user_id != current_user.id or not _active(share) or share.permissions != "download":
            abort(404)
        try:
            _, location = issue_download("vault", share.encrypted_file.storage_name, share.encrypted_file.filename, current_user.id)
        except (ValueError, FileNotFoundError):
            abort(404)
        except StorageBackendError:
            app.logger.exception("Shared-file storage is unavailable")
            abort(503)
        audit_action("share.download_requested", target_type="share", target_id=share.id)
        return redirect(location)

    @app.post("/revoke_share/<int:share_id>", endpoint="revoke_share")
    @login_required
    def revoke_share(share_id: int):  # type: ignore[no-untyped-def]
        share = db.session.get(SharedFile, share_id)
        if not share or share.shared_by_user_id != current_user.id:
            abort(404)
        share.is_active = False
        audit_action("share.revoked", target_type="share", target_id=share.id, commit=False)
        db.session.commit()
        return jsonify(success=True)
