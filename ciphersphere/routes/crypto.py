"""Encryption, decryption, and user-bound temporary download routes."""

from __future__ import annotations

import base64
import hashlib
import json
from io import BytesIO
from pathlib import Path
from typing import Any

from flask import Flask, abort, after_this_request, current_app, flash, render_template, send_file
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from ..extensions import db
from ..forms import DecryptForm, EncryptForm
from ..models import DownloadToken, EncryptedFile, utcnow
from ..storage_service import StorageBackendError, delete_storage, read_bytes
from .common import audit_action, issue_download, write_storage


def _manager():  # type: ignore[no-untyped-def]
    return current_app.extensions["encryption_manager"]


def _bytes(result: Any) -> bytes:
    value = result.get("data") if isinstance(result, dict) else result
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode()
    raise ValueError("The encryption engine returned invalid data.")


def _key(result: Any, fallback: str) -> str:
    if isinstance(result, dict) and result.get("key"):
        return str(result["key"])
    return fallback


def _file_payload(data: bytes, filename: str, algorithm: str) -> bytes:
    metadata = json.dumps(
        {"original_filename": secure_filename(filename) or "decrypted.bin", "file_size": len(data), "algorithm": algorithm},
        separators=(",", ":"),
    ).encode()
    return b"CSMD" + bytes([1]) + len(metadata).to_bytes(4, "big") + metadata + data


def _decrypt_file(data: bytes, key: str, algorithm: str) -> tuple[bytes, dict[str, Any] | None]:
    result = _manager().decrypt_data_with_metadata(data, key, algorithm)
    return _bytes(result), result.get("metadata") if result.get("has_metadata") else None


def register_crypto_routes(app: Flask) -> None:
    @app.route("/encrypt", methods=["GET", "POST"], endpoint="encrypt")
    @login_required
    def encrypt():  # type: ignore[no-untyped-def]
        form = EncryptForm()
        if form.validate_on_submit():
            has_text = bool((form.text_content.data or "").strip())
            has_file = bool(form.file.data and form.file.data.filename)
            if has_text == has_file:
                flash("Provide either text or one file.", "error")
                return render_template("encrypt.html", form=form)
            try:
                algorithm = form.algorithm.data
                key = form.key.data or str(_manager().generate_key(algorithm))
                original_name = "encrypted_text.txt"
                if has_text:
                    raw_result = _manager().encrypt_text(form.text_content.data, key, algorithm)
                    encrypted = _bytes(raw_result)
                    key = _key(raw_result, key)
                    original_size = len(form.text_content.data.encode())
                else:
                    upload = form.file.data
                    original_name = secure_filename(upload.filename) or "upload.bin"
                    original = upload.read()
                    if len(original) > current_app.config["MAX_CONTENT_LENGTH"]:
                        raise ValueError("The uploaded file exceeds the size limit.")
                    raw_result = _manager().encrypt_data(_file_payload(original, original_name, algorithm), key, algorithm)
                    encrypted = _bytes(raw_result)
                    key = _key(raw_result, key)
                    original_size = len(original)

                file_id: int | None = None
                download_url: str | None = None
                if form.save_to_vault.data:
                    storage_name = write_storage("vault", encrypted, suffix=".enc")
                    record = EncryptedFile(
                        user_id=current_user.id,
                        storage_name=storage_name,
                        filename=f"{original_name}.encrypted",
                        original_filename=original_name,
                        algorithm=algorithm,
                        file_size=original_size,
                        is_text=has_text,
                    )
                    db.session.add(record)
                    db.session.commit()
                    file_id = record.id
                else:
                    storage_name = write_storage("temp", encrypted, suffix=".enc")
                    _, download_url = issue_download("temp", storage_name, f"{original_name}.encrypted", current_user.id)
                audit_action("crypto.encrypt", details={"algorithm": algorithm, "kind": "text" if has_text else "file"}, target_type="encrypted_file", target_id=file_id)
                result = {
                    "data": base64.b64encode(encrypted).decode(),
                    "file_id": file_id,
                    "saved_to_vault": bool(file_id),
                    "download_url": download_url,
                }
                return render_template(
                    "encrypt_result.html", result=result, algorithm=algorithm, key=key,
                    is_text=has_text, filename=original_name,
                )
            except Exception as exc:
                db.session.rollback()
                current_app.logger.warning("Encryption failed: %s", exc)
                audit_action("crypto.encrypt_failed", details={"algorithm": form.algorithm.data}, success=False)
                flash("Encryption failed. Check the selected algorithm and input.", "error")
        return render_template("encrypt.html", form=form)

    @app.route("/decrypt", methods=["GET", "POST"], endpoint="decrypt")
    @login_required
    def decrypt():  # type: ignore[no-untyped-def]
        form = DecryptForm()
        if form.validate_on_submit():
            has_text = bool((form.text_content.data or "").strip())
            has_file = bool(form.file.data and form.file.data.filename)
            if has_text == has_file:
                flash("Provide either encrypted text or one encrypted file.", "error")
                return render_template("decrypt.html", form=form)
            try:
                algorithm, key = form.algorithm.data, form.key.data
                timestamp = utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                if has_text:
                    result = _manager().decrypt_text(form.text_content.data.strip(), key, algorithm)
                    value = result.get("data") if isinstance(result, dict) else result
                    decrypted_text = value.decode(errors="replace") if isinstance(value, bytes) else str(value)
                    audit_action("crypto.decrypt", details={"algorithm": algorithm, "kind": "text"})
                    return render_template(
                        "decrypt_result.html", decrypted_text=decrypted_text, algorithm=algorithm,
                        is_text=True, timestamp=timestamp,
                    )
                upload = form.file.data
                encrypted = upload.read()
                decrypted, metadata = _decrypt_file(encrypted, key, algorithm)
                fallback = Path(secure_filename(upload.filename) or "decrypted.bin").stem
                original_name = secure_filename(str((metadata or {}).get("original_filename") or fallback)) or "decrypted.bin"
                temp_name = write_storage("temp", decrypted, suffix=Path(original_name).suffix)
                token, download_url = issue_download("temp", temp_name, original_name, current_user.id)
                audit_action("crypto.decrypt", details={"algorithm": algorithm, "kind": "file"})
                return render_template(
                    "decrypt_result.html", decrypted_file=temp_name, original_filename=original_name,
                    algorithm=algorithm, file_size=len(decrypted), is_text=False, filename=original_name,
                    timestamp=timestamp, download_token=token, download_url=download_url,
                )
            except Exception as exc:
                current_app.logger.info("Decryption rejected: %s", exc)
                audit_action("crypto.decrypt_failed", details={"algorithm": form.algorithm.data}, success=False)
                flash("Decryption failed. Verify the algorithm, key, and input.", "error")
        return render_template("decrypt.html", form=form)

    @app.get("/downloads/<token>", endpoint="download_token")
    @login_required
    def download_token(token: str):  # type: ignore[no-untyped-def]
        digest = hashlib.sha256(token.encode()).hexdigest()
        record = DownloadToken.query.filter_by(token_hash=digest, user_id=current_user.id).first_or_404()
        now = utcnow()
        if record.used_at or record.expires_at < now:
            abort(410)
        try:
            payload = read_bytes(record.storage_area, record.relative_name)
        except (ValueError, FileNotFoundError):
            abort(404)
        except StorageBackendError:
            current_app.logger.exception("Private storage download failed")
            abort(503)
        consumed = (
            DownloadToken.query.filter(
                DownloadToken.id == record.id,
                DownloadToken.user_id == current_user.id,
                DownloadToken.used_at.is_(None),
                DownloadToken.expires_at >= now,
            )
            .update({DownloadToken.used_at: now}, synchronize_session=False)
        )
        if consumed != 1:
            db.session.rollback()
            abort(410)
        db.session.commit()
        audit_action("file.download", target_type="download", target_id=record.id)
        if record.storage_area == "temp":
            @after_this_request
            def remove_temp(response):  # type: ignore[no-untyped-def]
                try:
                    delete_storage("temp", record.relative_name)
                except StorageBackendError:
                    current_app.logger.warning("Could not remove temporary download object")
                return response
        return send_file(
            BytesIO(payload),
            as_attachment=True,
            download_name=record.download_name,
            mimetype="application/octet-stream",
        )
