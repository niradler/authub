from __future__ import annotations

from typing import Any

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import OctKey, OKPKey
from joserfc.jwt import JWTClaimsRegistry

from authub.errors import ConfigurationError
from authub.errors import InvalidTokenError as AuthubInvalidTokenError
from authub.models import TokenClaims
from authub.tokens.base import TokenService

_MIN_HS256_SECRET_LEN = 32


class JwtTokenService(TokenService):
    def __init__(
        self,
        key: OctKey | OKPKey,
        algorithm: str,
        verify_key: OKPKey | None = None,
        issuer: str = "authub",
        audience: str = "authub",
        leeway: int = 60,
    ) -> None:
        self._key = key
        self._algorithm = algorithm
        self._verify_key = verify_key
        self._issuer = issuer
        self._audience = audience
        self._leeway = leeway

    @classmethod
    def hs256(cls, secret: str, **kwargs: Any) -> JwtTokenService:
        if len(secret) < _MIN_HS256_SECRET_LEN:
            raise ConfigurationError(
                f"HS256 secret must be at least {_MIN_HS256_SECRET_LEN} characters"
            )
        key = OctKey.import_key(secret)
        return cls(key=key, algorithm="HS256", **kwargs)

    @classmethod
    def ed25519(cls, private_key_pem: bytes | None = None, **kwargs: Any) -> JwtTokenService:
        if private_key_pem is not None:
            key = OKPKey.import_key(private_key_pem)
        else:
            key = OKPKey.generate_key("Ed25519", auto_kid=True)
        return cls(key=key, algorithm="Ed25519", **kwargs)

    @classmethod
    def ed25519_verifier(cls, public_key_pem: bytes, **kwargs: Any) -> JwtTokenService:
        key = OKPKey.import_key(public_key_pem)
        return cls(key=key, algorithm="Ed25519", **kwargs)

    @property
    def public_key_pem(self) -> bytes:
        if not isinstance(self._key, OKPKey):
            raise ConfigurationError("public_key_pem is only available for asymmetric keys")
        return self._key.as_pem(private=False)

    async def sign(self, claims: dict[str, Any]) -> str:
        payload = {k: v for k, v in claims.items() if v is not None}
        payload["iss"] = self._issuer
        payload["aud"] = self._audience
        return jwt.encode(
            {"alg": self._algorithm},
            payload,
            self._key,
            algorithms=[self._algorithm],
        )

    async def verify(self, token: str) -> TokenClaims:
        try:
            key = self._verify_key if self._verify_key is not None else self._key
            decoded = jwt.decode(token, key, algorithms=[self._algorithm])
            registry = JWTClaimsRegistry(
                leeway=self._leeway,
                iss={"essential": True, "value": self._issuer},
                aud={"essential": True, "value": self._audience},
                sub={"essential": True},
                jti={"essential": True},
            )
            registry.validate(decoded.claims)
            raw = decoded.claims
            if raw.get("token_type") == "user" and "exp" not in raw:
                raise AuthubInvalidTokenError("user tokens must include exp")
            return TokenClaims(
                sub=raw["sub"],
                token_type=raw["token_type"],
                tenant_id=raw.get("tid", ""),
                email=raw.get("email"),
                name=raw.get("name"),
                roles=raw.get("roles", []),
                scopes=raw.get("scopes", []),
                jti=raw["jti"],
                iat=raw["iat"],
                exp=raw.get("exp"),
                claims=raw,
            )
        except AuthubInvalidTokenError:
            raise
        except (JoseError, ValueError) as exc:
            raise AuthubInvalidTokenError(str(exc)) from exc
