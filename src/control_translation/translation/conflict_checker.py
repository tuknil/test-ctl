"""Conflict/placement detection gate.

Delegates the actual conflict comparison to the adapter (only the adapter
knows how to compare a candidate to that target's existing policy shape).
This module is the capability-core-facing seam.
"""

from __future__ import annotations

from control_translation.adapters.base import TargetAdapter
from control_translation.policy_reader.base import PolicySnapshot


def detect_conflicts(
    adapter: TargetAdapter,
    candidate_content: str,
    snapshot: PolicySnapshot | None,
) -> list[str]:
    return adapter.detect_conflicts(candidate_content, snapshot)
