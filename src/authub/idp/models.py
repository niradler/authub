from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, SecretStr


class IdpClient(BaseModel):
    client_id: str
    client_secret: SecretStr | None = None
    redirect_uris: list[str]


class IdpUser(BaseModel):
    username: str
    password_hash: str
    sub: str
    claims: dict[str, Any] = Field(default_factory=dict)


class AuthCode(BaseModel):
    code: str
    client_id: str
    redirect_uri: str
    scope: str
    sub: str
    nonce: str | None
    code_challenge: str | None
    expires_at: int
