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
from control_translation.contracts import JsonBodyFieldFeature
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
_SYNTHETIC_REQUEST_HEADERS = frozenset(
    {
        "request-uri",
        "request_uri",
        "request-body",
        "request_body",
    }
)
_HEADER_VALUE_CONDITION = "requestHeaderValueMatch"


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

    def supports_feature(
        self,
        discriminator_description: str,
        json_body_field_feature: JsonBodyFieldFeature | None = None,
    ) -> bool:
        if json_body_field_feature is not None:
            return True
        text = discriminator_description.lower()
        return any(feature in text for feature in self.supported_features) or (
            "expression" in text or "syntax" in text
        )

    def validate_syntax(self, candidate_content: str) -> SyntaxValidationResult:
        try:
            document = json.loads(candidate_content)
        except json.JSONDecodeError as exc:
            return SyntaxValidationResult(
                valid=False,
                errors=[f"Candidate is not valid JSON: {exc}"],
            )

        if not isinstance(document, dict):
            return SyntaxValidationResult(
                valid=False,
                errors=["Akamai custom rule must be a JSON object."],
            )

        rules, wrapper_errors = self._rules(document)
        errors = list(wrapper_errors)
        for rule_index, rule in enumerate(rules):
            prefix = f"rules[{rule_index}]." if len(rules) > 1 or "rules" in document else ""
            errors.extend(self._rule_errors(rule, prefix=prefix))

        if errors:
            return SyntaxValidationResult(valid=False, errors=errors)
        return SyntaxValidationResult(valid=True)

    def _rules(self, document: dict[str, object]) -> tuple[list[dict], list[str]]:
        if "rules" not in document:
            return [document], []
        if set(document) != {"rules"}:
            return [], ["Akamai rule-set wrapper may contain only 'rules'."]
        values = document["rules"]
        if not isinstance(values, list) or not values:
            return [], ["Field 'rules' must be a non-empty array."]
        if any(not isinstance(rule, dict) for rule in values):
            return [], ["Every rules[] member must be an object."]
        return values, []

    def _rule_errors(self, rule: dict, *, prefix: str = "") -> list[str]:
        errors: list[str] = []
        forbidden = _FORBIDDEN_ACTION_KEYS.intersection(rule.keys())
        if forbidden:
            errors.append(
                f"{prefix}Custom rule body must not embed an action "
                f"({', '.join(sorted(forbidden))}); the action is assigned "
                "separately on the security policy."
            )

        if rule.get("operation") not in ("AND", "OR"):
            errors.append(f"{prefix}Field 'operation' must be 'AND' or 'OR'.")

        conditions = rule.get("conditions")
        if not isinstance(conditions, list) or not conditions:
            errors.append(f"{prefix}Field 'conditions' must be a non-empty array.")
        else:
            for index, condition in enumerate(conditions):
                errors.extend(self._condition_errors(index, condition, prefix=prefix))
        return errors

    def _condition_errors(
        self, index: int, condition: object, *, prefix: str = ""
    ) -> list[str]:
        prefix = f"{prefix}conditions[{index}]"
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
        if isinstance(value, list):
            valid_value = bool(value) and all(
                isinstance(item, str) and bool(item) for item in value
            )
        else:
            valid_value = isinstance(value, str) and bool(value)
        if not valid_value:
            errors.append(f"{prefix}.value must be a non-empty array or a string.")
        condition_type = condition.get("type")
        if condition_type == "argsPostJSONMatch":
            parameter = condition.get("parameter")
            any_field = (
                condition.get("sourceLocationKind") == "http-body-structured"
                and condition.get("sourceSelectorType") == "any-field"
                and condition.get("sourceSelector") in {"", "*"}
            )
            if (not isinstance(parameter, str) or not parameter.strip()) and not any_field:
                errors.append(
                    f"{prefix}.parameter must identify the JSON field for "
                    "argsPostJSONMatch."
                )
        header = condition.get("header")
        if condition_type == _HEADER_VALUE_CONDITION:
            any_header = (
                condition.get("sourceCarrier") == "header"
                and condition.get("sourceSelector") == "*"
            )
            if (not isinstance(header, str) or not header.strip()) and not any_header:
                errors.append(
                    f"{prefix}.header must name a real request header for "
                    "requestHeaderValueMatch."
                )
            elif (
                isinstance(header, str)
                and header.strip().lower() in _SYNTHETIC_REQUEST_HEADERS
            ):
                errors.append(
                    f"{prefix}.header {header!r} is synthetic; use pathMatch for "
                    "URI paths or an argsPost condition for request bodies."
                )
        elif "header" in condition:
            errors.append(
                f"{prefix}.header is valid only for requestHeaderValueMatch."
            )
        return errors

    def detect_conflicts(
        self, candidate_content: str, snapshot: PolicySnapshot | None
    ) -> list[str]:
        if snapshot is None:
            return []
        try:
            document = json.loads(candidate_content)
        except json.JSONDecodeError:
            return []
        if not isinstance(document, dict):
            return []
        rules, errors = self._rules(document)
        if errors:
            return []
        candidate_identities = {
            identity.strip().lower()
            for rule in rules
            for identity in (
                rule.get("name"),
                rule.get("sourceRuleId"),
            )
            if isinstance(identity, str) and identity.strip()
        }
        existing_identities = {
            identity.strip().lower()
            for identity in snapshot.existing_rule_ids
            if identity.strip()
        }
        conflicts: list[str] = []
        for identity in sorted(candidate_identities & existing_identities):
            conflicts.append(f"Existing rule identity already exists: {identity}")
        return conflicts
