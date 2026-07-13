"""Private binary storage with local-development and Supabase backends."""

from __future__ import annotations

from pathlib import Path

from flask import current_app
from supabase import Client, create_client


ALLOWED_AREAS = {"avatars", "temp", "vault"}


class StorageBackendError(RuntimeError):
    """Raised when private storage is unavailable or misconfigured."""


def _safe_name(area: str, relative_name: str) -> tuple[str, str]:
    if area not in ALLOWED_AREAS:
        raise ValueError("Unknown storage area.")
    if not relative_name or Path(relative_name).name != relative_name:
        raise ValueError("Unsafe storage name.")
    return area, relative_name


def uses_supabase_storage() -> bool:
    return current_app.config.get("STORAGE_BACKEND", "local") == "supabase"


def _local_root(area: str) -> Path:
    key = {"avatars": "AVATAR_FOLDER", "temp": "TEMP_FOLDER", "vault": "VAULT_FOLDER"}[area]
    return Path(current_app.config[key]).expanduser().resolve()


def local_storage_path(area: str, relative_name: str) -> Path:
    area, relative_name = _safe_name(area, relative_name)
    root = _local_root(area)
    candidate = (root / relative_name).resolve()
    if candidate.parent != root:
        raise ValueError("Unsafe storage path.")
    return candidate


def _supabase_client() -> Client:
    cached = current_app.extensions.get("private_storage_client")
    if cached is not None:
        return cached
    url = current_app.config.get("SUPABASE_URL", "")
    secret = current_app.config.get("SUPABASE_SERVICE_ROLE_KEY", "")
    if not url or not secret:
        raise StorageBackendError(
            "Supabase Storage requires SUPABASE_URL and a server-only SUPABASE_SECRET_KEY."
        )
    client = create_client(url, secret)
    current_app.extensions["private_storage_client"] = client
    return client


def _bucket():  # type: ignore[no-untyped-def]
    return _supabase_client().storage.from_(current_app.config["SUPABASE_STORAGE_BUCKET"])


def _object_name(area: str, relative_name: str) -> str:
    area, relative_name = _safe_name(area, relative_name)
    return f"{area}/{relative_name}"


def _is_missing(exc: Exception) -> bool:
    status = str(getattr(exc, "status", "") or getattr(exc, "status_code", ""))
    message = str(exc).lower()
    return status == "404" or "not found" in message or "object not found" in message


def store_bytes(
    area: str,
    relative_name: str,
    data: bytes,
    *,
    content_type: str = "application/octet-stream",
) -> None:
    if uses_supabase_storage():
        try:
            _bucket().upload(
                _object_name(area, relative_name),
                data,
                file_options={"content-type": content_type, "upsert": "false"},
            )
        except Exception as exc:  # storage3 uses response-backed exception types
            raise StorageBackendError("Private storage could not save the object.") from exc
        return
    path = local_storage_path(area, relative_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(data)
    except OSError as exc:
        raise StorageBackendError("Private storage could not save the object.") from exc


def read_bytes(area: str, relative_name: str) -> bytes:
    if uses_supabase_storage():
        try:
            return _bucket().download(_object_name(area, relative_name))
        except Exception as exc:  # storage3 uses response-backed exception types
            if _is_missing(exc):
                raise FileNotFoundError(relative_name) from exc
            raise StorageBackendError("Private storage could not read the object.") from exc
    path = local_storage_path(area, relative_name)
    try:
        return path.read_bytes()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise StorageBackendError("Private storage could not read the object.") from exc


def storage_exists(area: str, relative_name: str) -> bool:
    try:
        read_bytes(area, relative_name)
        return True
    except FileNotFoundError:
        return False


def delete_storage(area: str, relative_name: str | None) -> None:
    if not relative_name:
        return
    if uses_supabase_storage():
        try:
            _bucket().remove([_object_name(area, relative_name)])
        except Exception as exc:  # deletion is intentionally surfaced to the caller
            if not _is_missing(exc):
                raise StorageBackendError("Private storage could not delete the object.") from exc
        return
    path = local_storage_path(area, relative_name)
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise StorageBackendError("Private storage could not delete the object.") from exc
