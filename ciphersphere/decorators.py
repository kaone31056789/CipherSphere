"""Authorization decorators."""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, TypeVar, cast

from flask import abort
from flask_login import current_user, login_required

F = TypeVar("F", bound=Callable[..., Any])


def admin_required(view: F) -> F:
    @wraps(view)
    @login_required
    def wrapped(*args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
        if not current_user.is_active or not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)

    return cast(F, wrapped)
