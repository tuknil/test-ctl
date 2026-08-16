"""Akamai WAF target adapter.

Fixture-backed: syntax rules are a reasonable approximation of Akamai's
Kona/App&API Protector custom-rule shape, not verified against a real
tenant. Real API access is an open integration (see
`docs/assumptions-and-followups.md`).
"""

from __future__ import annotations

import re

from control_translation.adapters.base import SyntaxValidationResult
from control_translation.policy_reader.base import PolicySnapshot


_HEADER_RULE_RE = re.compile(
    r'^rule\s+"[^"]+"\s*:\s*match\s+header\("[^"]+"\)\s*~\s*/.+/\s*->\s*(block|deny)\s*$'
)


class AkamaiWafAdapter:
    target_technology = "akamai-waf"
    artifact_type = "akamai-waf-rule"
    supported_features: tuple[str, ...] = (
        "header",
        "content-type",
        "query-string",
        "uri",
        "body",
        "regex",
    )

    def supports_feature(self, discriminator_description: str) -> bool:
        text = discriminator_description.lower()
        return any(feature in text for feature in self.supported_features) or (
            "expression" in text or "syntax" in text
        )

    def validate_syntax(self, candidate_content: str) -> SyntaxValidationResult:
        if _HEADER_RULE_RE.match(candidate_content.strip()):
            return SyntaxValidationResult(valid=True)
        return SyntaxValidationResult(
            valid=False,
            errors=[
                "Candidate does not match expected akamai-waf-rule shape: "
                'rule "<name>": match header("<Header>") ~ /<regex>/ -> block'
            ],
        )

    def detect_conflicts(
        self, candidate_content: str, snapshot: PolicySnapshot | None
    ) -> list[str]:
        if snapshot is None:
            return []
        conflicts: list[str] = []
        for summary in snapshot.existing_rule_summaries:
            if "block" in summary.lower() and "content-type" in candidate_content.lower():
                if "content-type" in summary.lower():
                    conflicts.append(
                        f"Existing rule may overlap: {summary}"
                    )
        return conflicts
