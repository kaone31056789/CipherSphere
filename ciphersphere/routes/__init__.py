"""Route registration."""

from __future__ import annotations

from flask import Flask

from .admin import register_admin_routes
from .auth import register_auth_routes
from .core import register_core_routes
from .crypto import register_crypto_routes
from .profile import register_profile_routes
from .sharing import register_sharing_routes
from .vault import register_vault_routes


def register_routes(app: Flask) -> None:
    register_core_routes(app)
    register_auth_routes(app)
    register_crypto_routes(app)
    register_vault_routes(app)
    register_sharing_routes(app)
    register_profile_routes(app)
    register_admin_routes(app)
