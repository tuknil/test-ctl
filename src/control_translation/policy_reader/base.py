"""PolicyReader provider protocol.

This seam represents the "live-policy" capability the CFS depends on
(`docs/cfs-source.md`, and Janus `artifacts/spikes.md` live-policy spike).
No real Akamai / Palo Alto / SentinelOne API client exists yet. Only a
deterministic fixture implementation is provided; a real implementation is
future work (see `docs/assumptions-and-followups.md`).
"""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, Field


class PolicySnapshot(BaseModel):
    """A read of the current live policy/config for a target technology."""

    snapshot_id: str
    target_technology: str
    target_policy_context_id: str
    existing_rule_ids: list[str] = Field(default_factory=list)
    existing_rule_summaries: list[str] = Field(default_factory=list)
    is_fixture: bool = True


class PolicyReader(Protocol):
    """What the capability needs from the world to read current policy."""

    def read_snapshot(
        self, target_technology: str, target_policy_context_id: str
    ) -> PolicySnapshot | None:
        """Return the current policy snapshot, or None if unavailable."""
        ...
