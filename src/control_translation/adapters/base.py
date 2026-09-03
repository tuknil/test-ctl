"""TargetAdapter protocol.

Every target-technology integration implements this protocol. A real
integration (real Akamai/Palo Alto/SentinelOne API access) replaces the
fixture-backed logic inside an adapter without changing the capability core.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, Field

from control_translation.contracts import JsonBodyFieldFeature
from control_translation.policy_reader.base import PolicySnapshot


class SyntaxValidationResult(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)


class TargetAdapter(Protocol):
    """What the capability needs from a specific target control technology."""

    target_technology: str
    artifact_type: str
    supported_features: tuple[str, ...]

    def supports_feature(
        self,
        discriminator_description: str,
        json_body_field_feature: JsonBodyFieldFeature | None = None,
    ) -> bool:
        """Cheap mechanical check: can this target technology plausibly
        express the discriminator at all, before spending an agent call?"""
        ...

    def validate_syntax(self, candidate_content: str) -> SyntaxValidationResult:
        """Deterministic shape/syntax check for a proposed candidate
        artifact. This is the mechanical judge gate."""
        ...

    def detect_conflicts(
        self, candidate_content: str, snapshot: PolicySnapshot | None
    ) -> list[str]:
        """Return a list of conflict notes, empty if none detected."""
        ...
