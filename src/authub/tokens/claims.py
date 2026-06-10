from __future__ import annotations

import time
import uuid
from datetime import timedelta
from typing import Any

from authub.models import CanonicalIdentity, Principal


def build_user_claims(
    principal: Principal,
    identity: CanonicalIdentity,
    ttl: timedelta,
) -> dict[str, Any]:
    """Build the JWT payload for a user login. Always includes ``exp``."""
    now = int(time.time())
    return {
        "sub": principal.id,
        "token_type": "user",
        "tid": principal.tenant_id,
        "email": principal.email,
        "name": principal.name,
        "roles": list(principal.roles),
        "scopes": list(principal.scopes),
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + int(ttl.total_seconds()),
    }


def build_service_claims(
    principal: Principal,
    ttl: timedelta | None,
) -> dict[str, Any]:
    """Build the JWT payload for a service principal. Omits ``exp`` when ``ttl`` is ``None``."""
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": principal.id,
        "token_type": "service",
        "tid": principal.tenant_id,
        "scopes": list(principal.scopes),
        "roles": list(principal.roles),
        "jti": uuid.uuid4().hex,
        "iat": now,
    }
    if ttl is not None:
        payload["exp"] = now + int(ttl.total_seconds())
    return payload
