"""Generic/Palo-Alto-style firewall target adapter.

Fixture-backed: syntax rules are a plausible approximation of a generic
next-gen firewall rule shape, not verified against a real Palo Alto/other
vendor tenant. Real API access is an open integration (see
`docs/assumptions-and-followups.md`).
"""

from __future__ import annotations

import re

from control_translation.adapters.base import SyntaxValidationResult
from control_translation.policy_reader.base import PolicySnapshot


_FW_RULE_RE = re.compile(
    r"^rule\s+\"[^\"]+\"\s*:\s*(deny|allow)\s+(inbound|outbound)\s+"
    r"(tcp|udp|any)/(\d{1,5}|any)\s+from\s+\S+\s+to\s+\S+\s*$",
    re.IGNORECASE,
)


class FirewallGenericAdapter:
    target_technology = "firewall-generic"
    artifact_type = "firewall-rule"
    supported_features: tuple[str, ...] = (
        "port",
        "protocol",
        "source",
        "destination",
        "network",
    )

    def supports_feature(self, discriminator_description: str) -> bool:
        text = discriminator_description.lower()
        return any(
            keyword in text
            for keyword in ("port", "network", "inbound", "outbound", "connection")
        )

    def validate_syntax(self, candidate_content: str) -> SyntaxValidationResult:
        if _FW_RULE_RE.match(candidate_content.strip()):
            return SyntaxValidationResult(valid=True)
        return SyntaxValidationResult(
            valid=False,
            errors=[
                "Candidate does not match expected firewall-rule shape: "
                'rule "<name>": deny|allow inbound|outbound tcp|udp|any/<port|any> '
                "from <src> to <dst>"
            ],
        )

    def detect_conflicts(
        self, candidate_content: str, snapshot: PolicySnapshot | None
    ) -> list[str]:
        if snapshot is None:
            return []
        conflicts: list[str] = []
        lowered = candidate_content.lower()
        for summary in snapshot.existing_rule_summaries:
            if "allow" in summary.lower() and "deny" in lowered:
                conflicts.append(
                    f"Possible ordering conflict with existing rule: {summary}"
                )
        return conflicts
