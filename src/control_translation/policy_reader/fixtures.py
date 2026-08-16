"""Deterministic fixture PolicyReader.

Used by default (RUN_MODE=fixture) and by all offline tests. Represents a
plausible current policy snapshot for each fixture target technology.
"""

from __future__ import annotations

from control_translation.policy_reader.base import PolicySnapshot


_FIXTURE_SNAPSHOTS: dict[tuple[str, str], PolicySnapshot] = {
    ("akamai-waf", "akamai-policy:example:rev-17"): PolicySnapshot(
        snapshot_id="policy-snapshot:akamai:example:rev-17",
        target_technology="akamai-waf",
        target_policy_context_id="akamai-policy:example:rev-17",
        existing_rule_ids=["rule-1001", "rule-1002"],
        existing_rule_summaries=[
            "rule-1001: block known SQLi patterns in query string",
            "rule-1002: rate-limit login endpoint",
        ],
    ),
    ("firewall-generic", "firewall-policy:example:rev-4"): PolicySnapshot(
        snapshot_id="policy-snapshot:firewall:example:rev-4",
        target_technology="firewall-generic",
        target_policy_context_id="firewall-policy:example:rev-4",
        existing_rule_ids=["fw-rule-10", "fw-rule-11"],
        existing_rule_summaries=[
            "fw-rule-10: deny inbound on legacy management port",
            "fw-rule-11: allow outbound DNS",
        ],
    ),
}


class FixturePolicyReader:
    """Deterministic offline PolicyReader implementation."""

    def read_snapshot(
        self, target_technology: str, target_policy_context_id: str
    ) -> PolicySnapshot | None:
        return _FIXTURE_SNAPSHOTS.get((target_technology, target_policy_context_id))
