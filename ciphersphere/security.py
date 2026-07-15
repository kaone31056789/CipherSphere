"""Application security controls shared by the Flask factory and routes."""

from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Callable, Collection
from functools import wraps
from ipaddress import ip_address
from math import ceil
from threading import Lock
from time import monotonic
from typing import Any, TypeVar, cast

from flask import Flask, Response, current_app, make_response, request
from flask_login import current_user


F = TypeVar("F", bound=Callable[..., Any])


def client_address() -> str:
    """Return a bounded, validated address without trusting proxy headers by default."""
    candidate = request.remote_addr or "unknown"
    if current_app.config.get("TRUST_PROXY_HEADERS"):
        forwarded = request.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
        if forwarded:
            candidate = forwarded
    try:
        return str(ip_address(candidate))
    except ValueError:
        return "unknown"


def request_actor_key() -> str:
    """Prefer an authenticated subject and otherwise use the validated client address."""
    if getattr(current_user, "is_authenticated", False):
        return f"user:{current_user.get_id()}"
    return f"ip:{client_address()}"


class InMemoryRateLimiter:
    """A bounded, process-local sliding-window limiter.

    This is defense in depth for a single process. Production should also use the
    platform and Supabase Auth rate limits because serverless instances do not
    share memory.
    """

    def __init__(self) -> None:
        self._entries: OrderedDict[tuple[str, str], deque[float]] = OrderedDict()
        self._lock = Lock()

    def check(self, scope: str, actor: str, limit: int, window_seconds: int) -> int:
        if limit <= 0 or window_seconds <= 0:
            return 0
        now = monotonic()
        cutoff = now - window_seconds
        key = (scope, actor)
        max_keys = max(int(current_app.config.get("RATE_LIMIT_MAX_KEYS", 10_000)), 100)
        with self._lock:
            attempts = self._entries.pop(key, deque())
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            if len(attempts) >= limit:
                retry_after = max(1, ceil(window_seconds - (now - attempts[0])))
                self._entries[key] = attempts
                return retry_after
            attempts.append(now)
            self._entries[key] = attempts
            while len(self._entries) > max_keys:
                self._entries.popitem(last=False)
        return 0


rate_limiter = InMemoryRateLimiter()


def rate_limit(
    scope: str,
    *,
    limit_config: str,
    window_seconds: int,
    methods: Collection[str] | None = None,
) -> Callable[[F], F]:
    """Apply a small local abuse limit to a route."""
    allowed_methods = {method.upper() for method in methods} if methods else None

    def decorator(view: F) -> F:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
            if allowed_methods is None or request.method in allowed_methods:
                retry_after = rate_limiter.check(
                    scope,
                    request_actor_key(),
                    int(current_app.config[limit_config]),
                    window_seconds,
                )
                if retry_after:
                    response = make_response(
                        "Too many requests. Wait before trying again.", 429
                    )
                    response.headers["Retry-After"] = str(retry_after)
                    response.headers["Cache-Control"] = "no-store"
                    return response
            return view(*args, **kwargs)

        return cast(F, wrapped)

    return decorator


def validate_runtime_security(app: Flask) -> None:
    """Fail closed for insecure production configuration."""
    if not app.config.get("PRODUCTION"):
        return

    secret = str(app.config.get("SECRET_KEY") or "")
    if len(secret) < 32 or secret == "replace-with-a-long-random-value":
        raise RuntimeError("Production requires a stable SECRET_KEY of at least 32 characters.")
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite:"):
        raise RuntimeError("Production requires the configured Supabase PostgreSQL database.")
    if app.debug or app.config.get("TESTING"):
        raise RuntimeError("Debug and testing modes must be disabled in production.")
    if not str(app.config.get("SUPABASE_URL") or "").startswith("https://"):
        raise RuntimeError("Production requires an HTTPS SUPABASE_URL.")
    if not app.config.get("SUPABASE_ANON_KEY"):
        raise RuntimeError("Production requires SUPABASE_PUBLISHABLE_KEY.")
    if not str(app.config.get("SUPABASE_AUTH_URL") or "").startswith("https://"):
        raise RuntimeError("Production requires an HTTPS SUPABASE_AUTH_URL.")
    if not app.config.get("SUPABASE_AUTH_ANON_KEY"):
        raise RuntimeError("Production requires SUPABASE_AUTH_PUBLISHABLE_KEY.")
    for name in ("SUPABASE_PASSWORD_REDIRECT_URL", "SUPABASE_OAUTH_REDIRECT_URL"):
        if not str(app.config.get(name) or "").startswith("https://"):
            raise RuntimeError(f"Production requires an HTTPS {name}.")
    if not app.config.get("SESSION_COOKIE_SECURE") or not app.config.get(
        "REMEMBER_COOKIE_SECURE"
    ):
        raise RuntimeError("Production authentication cookies must be Secure.")
    if app.config.get("AUTO_CREATE_DATABASE"):
        raise RuntimeError("Production database schema must be managed by migrations.")
    if app.config.get("STORAGE_BACKEND") == "supabase" and not app.config.get(
        "SUPABASE_SERVICE_ROLE_KEY"
    ):
        raise RuntimeError("Supabase Storage requires server-only SUPABASE_SECRET_KEY.")
    if app.config.get("STORAGE_BACKEND") != "supabase" and app.config.get("VERCEL"):
        raise RuntimeError("Vercel requires STORAGE_BACKEND=supabase for persistent files.")
    if app.config.get("VERCEL") and int(app.config.get("MAX_CONTENT_LENGTH", 0)) > 4_194_304:
        raise RuntimeError("Vercel requires MAX_CONTENT_LENGTH=4194304 or smaller.")


def init_security_headers(app: Flask) -> None:
    """Install browser hardening headers for every application response."""
    policy = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "frame-src 'none'; "
        "img-src 'self' data:; "
        "manifest-src 'self'; "
        "media-src 'self'; "
        "object-src 'none'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "worker-src 'self'"
    )
    if app.config.get("PRODUCTION"):
        policy += "; upgrade-insecure-requests"

    @app.after_request
    def apply_security_headers(response: Response) -> Response:
        response.headers.setdefault("Content-Security-Policy", policy)
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), geolocation=(), microphone=(), payment=(), usb=()")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
        if app.config.get("PRODUCTION"):
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        if getattr(current_user, "is_authenticated", False):
            response.headers.setdefault("Cache-Control", "private, no-store")
            response.headers.setdefault("Pragma", "no-cache")
        return response
