from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import ValidationError

from authub.errors import MappingError
from authub.models import CanonicalIdentity, Mapping, RawIdentity


def extract(claims: dict[str, Any], path: str) -> Any:
    value: Any = claims
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
        if value is None:
            return None
    return value


def _scalar(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


_TRANSFORMS: dict[str, Callable[[str], str]] = {
    "lower": str.lower,
    "upper": str.upper,
    "strip": str.strip,
}


def register_transform(name: str, fn: Callable[[str], str]) -> None:
    _TRANSFORMS[name] = fn


class Mapper:
    def normalize(self, raw: RawIdentity, mapping: Mapping) -> CanonicalIdentity:
        external_id = _scalar(extract(raw.claims, mapping.external_id))
        if external_id is None or str(external_id) == "":
            raise MappingError(f"required claim {mapping.external_id!r} is missing or empty")

        fields: dict[str, Any] = {
            "external_id": str(external_id),
            "email": self._optional_str(raw, mapping.email),
            "name": self._optional_str(raw, mapping.name),
            "roles": as_list(extract(raw.claims, mapping.roles)) if mapping.roles else [],
            "attributes": {key: extract(raw.claims, path) for key, path in mapping.extra.items()},
        }
        self._apply_transforms(fields, mapping)
        try:
            return CanonicalIdentity(**fields, raw=raw.claims)
        except ValidationError as exc:
            raise MappingError(
                f"mapped identity failed validation: {exc.error_count()} error(s)"
            ) from exc

    @staticmethod
    def _optional_str(raw: RawIdentity, path: str | None) -> str | None:
        if path is None:
            return None
        value = _scalar(extract(raw.claims, path))
        return None if value is None else str(value)

    @staticmethod
    def _apply_transforms(fields: dict[str, Any], mapping: Mapping) -> None:
        for field_name, transform_name in mapping.transforms.items():
            transform = _TRANSFORMS.get(transform_name)
            if transform is None:
                raise MappingError(f"unknown transform {transform_name!r}")
            target = fields.get(field_name, fields["attributes"].get(field_name))
            if isinstance(target, str):
                try:
                    value = transform(target)
                except Exception as exc:
                    raise MappingError(f"transform {transform_name!r} raised an error") from exc
                if field_name in fields:
                    fields[field_name] = value
                else:
                    fields["attributes"][field_name] = value
