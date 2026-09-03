"""Palo Alto PAN-OS firewall target adapter.

Fixture-backed shape validation for a PAN-OS security policy rule. Accepts
either the CLI `set rulebase security rules ...` form or the XML `<entry>`
form under the security rulebase, both sourced from `docs/syntexresearch.md`.
Not verified against a real firewall/Panorama; live admin-key API access is
an open integration (see `docs/assumptions-and-followups.md`).

Note: applying a rule also requires its referenced address/service objects
and a `commit`; those steps are out of band for this candidate artifact.
"""

from __future__ import annotations

import re
from xml.etree import ElementTree

from control_translation.adapters.base import SyntaxValidationResult
from control_translation.policy_reader.base import PolicySnapshot

_VALID_ACTIONS = ("allow", "deny", "drop", "reset-client", "reset-server", "reset-both")

# CLI: set rulebase security rules <name> from <z> to <z> source <s>
#      destination <d> application <a> service <svc> action <act>
_CLI_RULE_RE = re.compile(
    r"^set\s+rulebase\s+security\s+rules\s+\"?[^\"\s]+\"?\s+"
    r"(?=.*\bfrom\s+\S+)"
    r"(?=.*\bto\s+\S+)"
    r"(?=.*\bsource\s+\S+)"
    r"(?=.*\bdestination\s+\S+)"
    r"(?=.*\bapplication\s+\S+)"
    r"(?=.*\bservice\s+\S+)"
    r"(?=.*\baction\s+(?:" + "|".join(_VALID_ACTIONS) + r")\b)",
    re.IGNORECASE,
)

_REQUIRED_XML_CHILDREN = ("from", "to", "source", "destination", "action")


class FirewallGenericAdapter:
    target_technology = "firewall-generic"
    artifact_type = "firewall-rule"
    supported_features: tuple[str, ...] = (
        "port",
        "protocol",
        "source",
        "destination",
        "network",
        "zone",
        "application",
    )

    def supports_feature(
        self, discriminator_description: str, json_body_field_feature=None
    ) -> bool:
        text = discriminator_description.lower()
        return any(
            keyword in text
            for keyword in (
                "port",
                "network",
                "inbound",
                "outbound",
                "connection",
                "zone",
            )
        )

    def validate_syntax(self, candidate_content: str) -> SyntaxValidationResult:
        content = candidate_content.strip()
        if content.startswith("<"):
            return self._validate_xml(content)
        if content.lower().startswith("set "):
            return self._validate_cli(content)
        return SyntaxValidationResult(
            valid=False,
            errors=[
                (
                    "Candidate must be a PAN-OS security rule in CLI 'set rulebase "
                    "security rules ...' form or XML '<entry>' form."
                )
            ],
        )

    def _validate_cli(self, content: str) -> SyntaxValidationResult:
        if _CLI_RULE_RE.match(content):
            return SyntaxValidationResult(valid=True)
        return SyntaxValidationResult(
            valid=False,
            errors=[
                "Candidate does not match expected PAN-OS CLI shape: "
                "set rulebase security rules <name> from <zone> to <zone> "
                "source <src> destination <dst> application <app> service "
                "<svc> action <" + "|".join(_VALID_ACTIONS) + ">"
            ],
        )

    def _validate_xml(self, content: str) -> SyntaxValidationResult:
        try:
            entry = ElementTree.fromstring(content)
        except ElementTree.ParseError as exc:
            return SyntaxValidationResult(
                valid=False, errors=[f"Candidate is not valid XML: {exc}"]
            )
        errors: list[str] = []
        if entry.tag != "entry" or not entry.get("name"):
            errors.append("Root element must be <entry name=\"...\">.")
        for child in _REQUIRED_XML_CHILDREN:
            if entry.find(child) is None:
                errors.append(f"Missing required element <{child}>.")
        action_el = entry.find("action")
        if action_el is not None and (action_el.text or "").strip() not in _VALID_ACTIONS:
            errors.append(
                f"<action> must be one of: {', '.join(_VALID_ACTIONS)}."
            )
        if errors:
            return SyntaxValidationResult(valid=False, errors=errors)
        return SyntaxValidationResult(valid=True)

    def detect_conflicts(
        self, candidate_content: str, snapshot: PolicySnapshot | None
    ) -> list[str]:
        if snapshot is None:
            return []
        conflicts: list[str] = []
        lowered = candidate_content.lower()
        candidate_is_deny = "action deny" in lowered or "<action>deny</action>" in lowered
        for summary in snapshot.existing_rule_summaries:
            if candidate_is_deny and "allow" in summary.lower():
                conflicts.append(
                    f"Possible ordering conflict with existing rule: {summary}"
                )
        return conflicts
