"""Syntax validation gate (the mechanical "judge" for artifact shape).

Delegates the actual per-target syntax check to the adapter, since only the
adapter knows the target stack's rule shape. This module exists as the
capability-core-facing seam so `engine.py` does not depend directly on
adapter internals.
"""

from __future__ import annotations

from control_translation.adapters.base import SyntaxValidationResult, TargetAdapter


def validate(adapter: TargetAdapter, candidate_content: str) -> SyntaxValidationResult:
    if not candidate_content or not candidate_content.strip():
        return SyntaxValidationResult(valid=False, errors=["Candidate content is empty."])
    return adapter.validate_syntax(candidate_content)
