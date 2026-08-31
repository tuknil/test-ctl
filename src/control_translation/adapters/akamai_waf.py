"""Akamai WAF target adapter.

Fixture-backed shape validation for an Akamai Application Security custom
rule (App & API Protector / Kona Site Defender). The accepted shape follows
Akamai's documented custom-rule JSON (`operation` + `conditions[]`), sourced
from `docs/syntexresearch.md`. It is NOT verified against a real tenant; live
EdgeGrid API access is an open integration (see
`docs/assumptions-and-followups.md`).

Note: the rule action (alert/deny/none) is assigned separately when the rule
is attached to a security policy, so a valid custom rule body must NOT embed
an action.
"""

from __future__ import annotations

import json

from control_translation.adapters.base import SyntaxValidationResult
from control_translation.policy_reader.base import PolicySnapshot


# Documented Akamai custom-rule condition `type` values (subset used here).
_VALID_CONDITION_TYPES = frozenset(
    {
        "requestHeaderMatch",
        "requestHeaderValueMatch",
        "argsPostMatch",
        "argsPostJSONMatch",
        "argsPostXMLMatch",
        "pathMatch",
        "uriQueryMatch",
        "ipMatch",
        "requestMethodMatch",
        "cookieMatch",
    }
)

# Keys that indicate an action was (incorrectly) embedded in the rule body.
_FORBIDDEN_ACTION_KEYS = frozenset({"action", "deny", "alert"})


class AkamaiWafAdapter:
    target_technology = "akamai-waf"
    artifact_type = "akamai-waf-rule"
    supported_features: tuple[str, ...] = (
        "header",
        "content-type",
        "query-string",
        "uri",
        "path",
        "request",
        "body",
        "argument",
        "parameter",
        "cookie",
        "method",
        "ip",
        "regex",
        "sql injection",
    )

    def supports_feature(self, discriminator_description: str) -> bool:
        text = discriminator_description.lower()
        return any(feature in text for feature in self.supported_features) or (
            "expression" in text or "syntax" in text
        )

    def validate_syntax(self, candidate_content: str) -> SyntaxValidationResult:
        try:
            rule = json.loads(candidate_content)
        except json.JSONDecodeError as exc:
            return SyntaxValidationResult(
                valid=False,
                errors=[f"Candidate is not valid JSON: {exc}"],
            )

        if not isinstance(rule, dict):
            return SyntaxValidationResult(
                valid=False,
                errors=["Akamai custom rule must be a JSON object."],
            )

        errors: list[str] = []
        forbidden = _FORBIDDEN_ACTION_KEYS.intersection(rule.keys())
        if forbidden:
            errors.append(
                "Custom rule body must not embed an action "
                f"({', '.join(sorted(forbidden))}); the action is assigned "
                "separately on the security policy."
            )

        if rule.get("operation") not in ("AND", "OR"):
            errors.append("Field 'operation' must be 'AND' or 'OR'.")

        conditions = rule.get("conditions")
        if not isinstance(conditions, list) or not conditions:
            errors.append("Field 'conditions' must be a non-empty array.")
        else:
            for index, condition in enumerate(conditions):
                errors.extend(self._condition_errors(index, condition))

        if errors:
            return SyntaxValidationResult(valid=False, errors=errors)
        return SyntaxValidationResult(valid=True)

    def _condition_errors(self, index: int, condition: object) -> list[str]:
        prefix = f"conditions[{index}]"
        if not isinstance(condition, dict):
            return [f"{prefix} must be an object."]
        errors: list[str] = []
        if condition.get("type") not in _VALID_CONDITION_TYPES:
            errors.append(
                f"{prefix}.type {condition.get('type')!r} is not a recognized "
                "Akamai condition type."
            )
        if not isinstance(condition.get("positiveMatch"), bool):
            errors.append(f"{prefix}.positiveMatch must be a boolean.")
        value = condition.get("value")
        if not (isinstance(value, list) and value) and not isinstance(value, str):
            errors.append(f"{prefix}.value must be a non-empty array or a string.")
        return errors

    def detect_conflicts(
        self, candidate_content: str, snapshot: PolicySnapshot | None
    ) -> list[str]:
        if snapshot is None:
            return []
        try:
            rule = json.loads(candidate_content)
        except json.JSONDecodeError:
            return []
        condition_types = {
            c.get("type")
            for c in rule.get("conditions", [])
            if isinstance(c, dict)
        }
        conflicts: list[str] = []
        for summary in snapshot.existing_rule_summaries:
            lowered = summary.lower()
            if "content-type" in lowered and "requestHeaderValueMatch" in condition_types:
                conflicts.append(f"Existing rule may overlap: {summary}")
            elif "query string" in lowered and "uriQueryMatch" in condition_types:
                conflicts.append(f"Existing rule may overlap: {summary}")
        return conflicts
