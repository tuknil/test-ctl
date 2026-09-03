"""Safe serialization helpers for comprehensive deployment diagnostics."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

_REDACTED = "[REDACTED]"
_SECRET_KEYS = {
    "access_token",
    "api_key",
    "authorization",
    "client_secret",
    "credential",
    "credentials",
    "databricks_token",
    "idempotency_key",
    "password",
    "secret",
    "token",
}
_ARTIFACT_CONTENT_KEYS = {
    "artifact_content",
    "candidate_content",
    "content_ref",
}


def sanitize_for_logging(value: Any, *, parent_key: str | None = None) -> Any:
    """Recursively redact credentials and deployable candidate content."""
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json", by_alias=True)
    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for raw_key, child in value.items():
            key = str(raw_key)
            normalized = key.lower()
            if (
                _is_secret_key(normalized)
                or normalized in _ARTIFACT_CONTENT_KEYS
                or (parent_key == "json_body_field_feature" and normalized == "value")
            ):
                sanitized[key] = _REDACTED
            else:
                sanitized[key] = sanitize_for_logging(child, parent_key=normalized)
        return sanitized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [sanitize_for_logging(item, parent_key=parent_key) for item in value]
    if isinstance(value, bytes):
        return f"[BYTES length={len(value)}]"
    return value


def diagnostic_json(value: Any) -> str:
    """Serialize a sanitized diagnostic document as compact JSON."""
    return json.dumps(
        sanitize_for_logging(value),
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def _is_secret_key(key: str) -> bool:
    return key in _SECRET_KEYS or any(
        key.endswith(f"_{suffix}") for suffix in ("api_key", "password", "secret", "token")
    )
