"""Route helpers for audits, safe storage, and one-time downloads."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import timedelta
from typing import Any

from flask import current_app, request, url_for
from flask_login import current_user
from werkzeug.utils import secure_filename

from ..extensions import db
from ..models import ActivityLog, DownloadToken, utcnow
from ..security import client_address
from ..storage_service import (
    local_storage_path,
    storage_exists,
    store_bytes,
)


def audit_action(
    action: str,
    *,
    details: str | dict[str, Any] | None = None,
    user_id: int | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    success: bool = True,
    commit: bool = True,
) -> ActivityLog:
    actor_id = user_id
    if actor_id is None and getattr(current_user, "is_authenticated", False):
        actor_id = current_user.id
    log = ActivityLog(
        user_id=actor_id,
        action=action,
        details=json.dumps(details, sort_keys=True) if isinstance(details, dict) else details,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        success=success,
        ip_address=client_address()[:45],
        user_agent=request.user_agent.string[:500],
    )
    db.session.add(log)
    if commit:
        db.session.commit()
    return log


def storage_path(area: str, relative_name: str):  # type: ignore[no-untyped-def]
    """Return a local path for compatibility with local-only maintenance code."""
    return local_storage_path(area, relative_name)


def write_storage(area: str, data: bytes, *, suffix: str = "") -> str:
    relative_name = f"{secrets.token_hex(24)}{suffix[:20]}"
    store_bytes(area, relative_name, data)
    return relative_name


def issue_download(area: str, relative_name: str, download_name: str, user_id: int) -> tuple[str, str]:
    # Resolve now so an invalid or missing storage area cannot be tokenized.
    if not storage_exists(area, relative_name):
        raise FileNotFoundError(relative_name)
    token = secrets.token_urlsafe(32)
    record = DownloadToken(
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        user_id=user_id,
        storage_area=area,
        relative_name=relative_name,
        download_name=secure_filename(download_name) or "download.bin",
        expires_at=utcnow() + timedelta(seconds=current_app.config["DOWNLOAD_TOKEN_TTL_SECONDS"]),
    )
    db.session.add(record)
    db.session.commit()
    return token, url_for("download_token", token=token)
