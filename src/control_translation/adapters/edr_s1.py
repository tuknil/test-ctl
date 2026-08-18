"""SentinelOne (S1) EDR target adapter.

Fixture-backed shape validation for a SentinelOne STAR (Storyline Active
Response) custom detection rule, sourced from `docs/syntexresearch.md`. The
accepted shape is the `POST /web/api/v2.1/cloud-detection/rules` JSON body
(`data{name, s1ql, severity, treatAsThreat, ...}`). Not verified against a
real console; the authoritative v2.1 schema is console-gated and live API
access is an open integration (see `docs/assumptions-and-followups.md`).

Whether EDR/S1 is in the Janus MVP scope is still unconfirmed; that is a
scope question, not a feasibility one (STAR can express the pattern).
"""

from __future__ import annotations

import json

from control_translation.adapters.base import SyntaxValidationResult
from control_translation.policy_reader.base import PolicySnapshot


_VALID_SEVERITIES = frozenset({"Low", "Medium", "High", "Critical"})
_VALID_TREAT_AS_THREAT = frozenset({"Malicious", "Suspicious", "UNDEFINED"})


class EdrS1Adapter:
    target_technology = "edr-s1"
    artifact_type = "edr-rule"
    supported_features: tuple[str, ...] = (
        "process",
        "process-chain",
        "process-tree",
        "network",
        "file",
        "s1ql",
    )

    def supports_feature(self, discriminator_description: str) -> bool:
        text = discriminator_description.lower()
        return any(
            keyword in text
            for keyword in (
                "process",
                "spawn",
                "chain",
                "tree",
                "network",
                "connection",
                "file",
            )
        )

    def validate_syntax(self, candidate_content: str) -> SyntaxValidationResult:
        try:
            rule = json.loads(candidate_content)
        except json.JSONDecodeError as exc:
            return SyntaxValidationResult(
                valid=False, errors=[f"Candidate is not valid JSON: {exc}"]
            )

        if not isinstance(rule, dict):
            return SyntaxValidationResult(
                valid=False, errors=["STAR rule must be a JSON object."]
            )

        data = rule.get("data")
        if not isinstance(data, dict):
            return SyntaxValidationResult(
                valid=False, errors=["Field 'data' must be an object."]
            )

        errors: list[str] = []
        if not (isinstance(data.get("name"), str) and data["name"].strip()):
            errors.append("data.name must be a non-empty string.")
        if not (isinstance(data.get("s1ql"), str) and data["s1ql"].strip()):
            errors.append("data.s1ql must be a non-empty S1QL query string.")
        if data.get("severity") not in _VALID_SEVERITIES:
            errors.append(
                f"data.severity must be one of: {', '.join(sorted(_VALID_SEVERITIES))}."
            )
        if data.get("treatAsThreat") not in _VALID_TREAT_AS_THREAT:
            errors.append(
                "data.treatAsThreat must be one of: "
                f"{', '.join(sorted(_VALID_TREAT_AS_THREAT))}."
            )
        query_lang = data.get("queryLang", "2.0")
        if query_lang not in ("1.0", "2.0"):
            errors.append("data.queryLang must be '1.0' or '2.0'.")

        if errors:
            return SyntaxValidationResult(valid=False, errors=errors)
        return SyntaxValidationResult(valid=True)

    def detect_conflicts(
        self, candidate_content: str, snapshot: PolicySnapshot | None
    ) -> list[str]:
        # No fixture S1 policy snapshots exist yet; nothing to compare against.
        return []
