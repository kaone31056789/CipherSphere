"""Supabase Auth integration with a server-owned application profile mirror."""

from __future__ import annotations

import json
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from flask import current_app
from sqlalchemy import func, or_

from .extensions import db
from .models import User, utcnow

try:
    from supabase import ClientOptions, create_client
except ImportError:
    create_client = None  # type: ignore[assignment]
    ClientOptions = None  # type: ignore[assignment,misc]


class AuthenticationError(ValueError):
    """A safe authentication error that can be shown to users."""


class _OperationStorage:
    """In-memory Supabase storage that exposes the one-time PKCE verifier."""

    def __init__(self) -> None:
        self._items: dict[str, str] = {}
        self.code_verifier: str | None = None

    def get_item(self, key: str) -> str | None:
        return self._items.get(key)

    def set_item(self, key: str, value: str) -> None:
        self._items[key] = value
        if key.endswith("-code-verifier"):
            self.code_verifier = value

    def remove_item(self, key: str) -> None:
        self._items.pop(key, None)


def find_user(identifier: str) -> User | None:
    normalized = identifier.strip().lower()
    if not normalized:
        return None
    return User.query.filter(
        or_(func.lower(User.email) == normalized, func.lower(User.username) == normalized)
    ).first()


def is_designated_admin(email: str) -> bool:
    """Check the server-owned admin allowlist using exact email matching."""
    configured = current_app.config.get("ADMIN_EMAILS") or ()
    return email.strip().casefold() in configured


def ensure_designated_admin(user: User) -> bool:
    """Promote an allowlisted profile without trusting OAuth user metadata."""
    if user.is_admin or not is_designated_admin(user.email):
        return False
    user.role = "admin"
    db.session.commit()
    return True


class SupabaseAuthProvider:
    """Create an isolated Supabase client for every authentication operation."""

    name = "supabase"

    def _client(
        self,
        *,
        admin: bool = False,
        storage: _OperationStorage | None = None,
        flow_type: Literal["implicit", "pkce"] = "implicit",
    ):  # type: ignore[no-untyped-def]
        if create_client is None or ClientOptions is None:
            raise RuntimeError("Install the supabase package before starting CipherSphere.")
        url = current_app.config.get("SUPABASE_AUTH_URL", "")
        key_name = (
            "SUPABASE_AUTH_SERVICE_ROLE_KEY"
            if admin
            else "SUPABASE_AUTH_ANON_KEY"
        )
        key = current_app.config.get(key_name, "")
        if not url or not key:
            raise RuntimeError(f"SUPABASE_AUTH_URL and {key_name} must be configured.")
        options: dict[str, Any] = {
            "persist_session": False,
            "auto_refresh_token": False,
            "flow_type": flow_type,
        }
        if storage is not None:
            options["storage"] = storage
        return create_client(url, key, options=ClientOptions(**options))

    def google_provider_enabled(self) -> bool | None:
        """Return the public Google-provider state, or None when it cannot be read."""
        url = current_app.config.get("SUPABASE_AUTH_URL", "").rstrip("/")
        key = current_app.config.get("SUPABASE_AUTH_ANON_KEY", "")
        if not url or not key:
            return None
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            return None
        request = Request(
            f"{url}/auth/v1/settings",
            headers={"Accept": "application/json", "apikey": key},
        )
        try:
            # The parsed URL is restricted to HTTPS before this request is built.
            with urlopen(request, timeout=4) as response:  # nosec B310
                settings = json.load(response)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError):
            return None
        external = settings.get("external", {}) if isinstance(settings, dict) else {}
        enabled = external.get("google") if isinstance(external, dict) else None
        return enabled if isinstance(enabled, bool) else None

    @staticmethod
    def _mirror(subject: str, email: str, metadata: dict[str, Any]) -> User:
        user = User.query.filter_by(auth_subject=subject).first() or find_user(email)
        username = str(metadata.get("username") or email.split("@", 1)[0])[:80]
        full_name = str(metadata.get("full_name") or username)[:120]
        if user:
            user.auth_subject = subject
            user.email = email.lower()
            if is_designated_admin(email):
                user.role = "admin"
            db.session.commit()
            return user

        candidate = username
        suffix = 1
        while User.query.filter(func.lower(User.username) == candidate.lower()).first():
            suffix += 1
            candidate = f"{username[:72]}_{suffix}"
        user = User(
            auth_subject=subject,
            username=candidate,
            email=email.lower(),
            full_name=full_name or candidate,
            role="admin" if is_designated_admin(email) else "user",
        )
        db.session.add(user)
        db.session.commit()
        return user

    def register(self, **data: Any) -> User:
        try:
            response = self._client().auth.sign_up(
                {
                    "email": data["email"],
                    "password": data["password"],
                    "options": {
                        "email_redirect_to": current_app.config[
                            "SUPABASE_PASSWORD_REDIRECT_URL"
                        ].replace("/reset_password", "/login"),
                        "data": {
                            "username": data["username"],
                            "full_name": data["full_name"],
                        },
                    },
                }
            )
        except Exception as exc:
            raise AuthenticationError("Supabase could not create the account.") from exc
        remote = getattr(response, "user", None)
        if not remote:
            raise AuthenticationError("Supabase could not create the account.")
        return self._mirror(
            str(remote.id), str(remote.email), dict(remote.user_metadata or {})
        )

    def authenticate(self, identifier: str, password: str) -> User:
        local = find_user(identifier)
        email = local.email if local else identifier.strip().lower()
        if "@" not in email:
            raise AuthenticationError("Use your email address to sign in.")
        try:
            response = self._client().auth.sign_in_with_password(
                {"email": email, "password": password}
            )
        except Exception as exc:
            raise AuthenticationError("Invalid email or password.") from exc
        remote = getattr(response, "user", None)
        if not remote:
            raise AuthenticationError("Invalid email or password.")
        user = self._mirror(
            str(remote.id), str(remote.email), dict(remote.user_metadata or {})
        )
        if not user.is_active:
            raise AuthenticationError("This account is disabled.")
        return user

    def google_oauth_url(self, redirect_url: str) -> tuple[str, str]:
        """Create a Google OAuth authorization URL and its one-time PKCE verifier."""
        if self.google_provider_enabled() is False:
            raise AuthenticationError(
                "Google sign-in is not enabled for this Supabase project yet."
            )
        storage = _OperationStorage()
        try:
            response = self._client(storage=storage, flow_type="pkce").auth.sign_in_with_oauth(
                {
                    "provider": "google",
                    "options": {
                        "redirect_to": redirect_url,
                        "scopes": "openid email profile",
                    },
                }
            )
        except Exception as exc:
            raise AuthenticationError("Google sign-in could not be started.") from exc
        authorization_url = str(getattr(response, "url", "") or "")
        if not authorization_url or not storage.code_verifier:
            raise AuthenticationError("Google sign-in could not be started.")
        return authorization_url, storage.code_verifier

    def complete_google_oauth(
        self, auth_code: str, code_verifier: str, redirect_url: str
    ) -> User:
        """Exchange a Google PKCE code and mirror the authenticated profile."""
        if not auth_code or not code_verifier:
            raise AuthenticationError("The Google sign-in request is invalid or expired.")
        try:
            response = self._client(flow_type="pkce").auth.exchange_code_for_session(
                {
                    "auth_code": auth_code,
                    "code_verifier": code_verifier,
                    "redirect_to": redirect_url,
                }
            )
        except Exception as exc:
            raise AuthenticationError("Google sign-in could not be completed.") from exc
        remote = getattr(response, "user", None)
        if remote is None:
            remote_session = getattr(response, "session", None)
            remote = getattr(remote_session, "user", None)
        remote_email = str(getattr(remote, "email", "") or "").strip().lower()
        if remote is None or not remote_email:
            raise AuthenticationError("Google did not return a usable email address.")
        user = self._mirror(
            str(remote.id), remote_email, dict(remote.user_metadata or {})
        )
        if not user.is_active:
            raise AuthenticationError("This account is disabled.")
        return user

    def request_password_reset(self, identifier: str) -> User | None:
        local = find_user(identifier)
        email = local.email if local else identifier.strip().lower()
        if "@" in email:
            try:
                self._client().auth.reset_password_email(
                    email,
                    options={
                        "redirect_to": current_app.config[
                            "SUPABASE_PASSWORD_REDIRECT_URL"
                        ]
                    },
                )
            except Exception:
                # Return the same public response for unknown and known accounts.
                return local
        return local

    def complete_password_recovery(
        self, access_token: str, refresh_token: str, new_password: str
    ) -> User:
        if not access_token or not refresh_token:
            raise AuthenticationError(
                "Open the latest password-reset link from your email and try again."
            )
        try:
            client = self._client()
            session_response = client.auth.set_session(access_token, refresh_token)
            remote = getattr(session_response, "user", None)
            update_response = client.auth.update_user({"password": new_password})
            remote = getattr(update_response, "user", None) or remote
        except Exception as exc:
            raise AuthenticationError("The password-reset link is invalid or expired.") from exc
        if not remote:
            raise AuthenticationError("The password-reset link is invalid or expired.")
        user = self._mirror(
            str(remote.id), str(remote.email), dict(remote.user_metadata or {})
        )
        user.password_changed_at = utcnow()
        user.session_version += 1
        db.session.commit()
        return user

    def change_password(self, user: User, current_password: str, new_password: str) -> None:
        try:
            client = self._client()
            response = client.auth.sign_in_with_password(
                {"email": user.email, "password": current_password}
            )
            if not getattr(response, "session", None):
                raise AuthenticationError("The current password is incorrect.")
            client.auth.update_user({"password": new_password})
        except AuthenticationError:
            raise
        except Exception as exc:
            raise AuthenticationError("The current password is incorrect.") from exc
        user.password_changed_at = utcnow()
        user.session_version += 1
        db.session.commit()

    def create_admin(self, **data: Any) -> User:
        try:
            response = self._client(admin=True).auth.admin.create_user(
                {
                    "email": data["email"],
                    "password": data["password"],
                    "email_confirm": True,
                    "user_metadata": {
                        "username": data["username"],
                        "full_name": data["full_name"],
                    },
                }
            )
        except Exception as exc:
            raise AuthenticationError("Supabase could not create the administrator.") from exc
        remote = getattr(response, "user", response)
        user = self._mirror(
            str(remote.id), str(remote.email), dict(remote.user_metadata or {})
        )
        user.role = "admin"
        user.is_active = True
        db.session.commit()
        return user

    def delete_user(self, user: User) -> None:
        """Delete the Supabase identity so a removed account cannot sign in again."""
        if not user.auth_subject:
            raise AuthenticationError("This account is not linked to a Supabase identity.")
        try:
            self._client(admin=True).auth.admin.delete_user(str(user.auth_subject))
        except Exception as exc:
            raise AuthenticationError(
                "Supabase could not delete the identity. Configure the server-only secret key and try again."
            ) from exc


def get_auth_service() -> SupabaseAuthProvider:
    provider = current_app.extensions.get("auth_service")
    if not isinstance(provider, SupabaseAuthProvider):
        raise RuntimeError("Supabase authentication service was not initialized.")
    return provider


def build_auth_service(provider_name: str) -> SupabaseAuthProvider:
    if provider_name != "supabase":
        raise RuntimeError("AUTH_PROVIDER must be 'supabase'.")
    return SupabaseAuthProvider()
