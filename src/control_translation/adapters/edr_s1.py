"""SentinelOne/EDR target adapter.

Minimal, typed stub. Whether EDR/S1 is even in MVP scope is unconfirmed (see
`docs/assumptions-and-followups.md`). This adapter accepts a narrow
process-tree-rule syntax as a placeholder and otherwise declines with
`unsupported-feature`. No real S1 API integration exists.
"""

from __future__ import annotations

import re

from control_translation.adapters.base import SyntaxValidationResult
from control_translation.policy_reader.base import PolicySnapshot


_EDR_RULE_RE = re.compile(
    r"^detect\s+process-chain\s*:\s*.+->.+->.+\s*=>\s*(block|alert)\s*$",
    re.IGNORECASE,
)


class EdrS1Adapter:
    target_technology = "edr-s1"
    artifact_type = "edr-rule"
    supported_features: tuple[str, ...] = ("process-chain", "process-tree")

    def supports_feature(self, discriminator_description: str) -> bool:
        text = discriminator_description.lower()
        return "process" in text and ("chain" in text or "tree" in text or "spawn" in text)

    def validate_syntax(self, candidate_content: str) -> SyntaxValidationResult:
        if _EDR_RULE_RE.match(candidate_content.strip()):
            return SyntaxValidationResult(valid=True)
        return SyntaxValidationResult(
            valid=False,
            errors=[
                "Candidate does not match expected edr-rule shape: "
                "detect process-chain: <a> -> <b> -> <c> => block|alert"
            ],
        )

    def detect_conflicts(
        self, candidate_content: str, snapshot: PolicySnapshot | None
    ) -> list[str]:
        # No fixture EDR policy snapshots exist yet; nothing to compare against.
        return []
