"""Terminal-state enum and routing precedence for control-translation.

Derived from `docs/cfs-source.md` (CFS §4). Precedence matters: when more than
one condition applies, the earliest-listed state below wins.
"""

from __future__ import annotations

from enum import Enum


class TerminalState(str, Enum):
    """Terminal states the capability may emit for a single invocation."""

    TRANSLATED = "translated"
    CANNOT_EXPRESS = "cannot-express"
    INSUFFICIENT_CONTEXT = "insufficient-context"
    SCOPE_DECLINED = "scope-declined"
    MALFUNCTION = "malfunction"


class OutcomeReasonCode(str, Enum):
    """Reason codes bound to a terminal state, per CFS §2 `outcome_reason.code`."""

    TRANSLATED = "translated"
    UNSUPPORTED_TARGET_TECHNOLOGY = "unsupported-target-technology"
    UNSUPPORTED_FEATURE = "unsupported-feature"
    POLICY_CONFLICT = "policy-conflict"
    INSUFFICIENT_POLICY_CONTEXT = "insufficient-policy-context"
    INSUFFICIENT_PATTERN_CONTEXT = "insufficient-pattern-context"
    INVALID_INPUT = "invalid-input"
    PROVIDER_FAILURE = "provider-failure"
    RESULT_ASSEMBLY_FAILURE = "result-assembly-failure"


# Terminal-state precedence order, most-authoritative first. The orchestration
# core (`capability.py`) evaluates gates in this order and stops at the first
# one that fires. This mirrors CFS §4: scope decisions and missing-context
# checks must be resolved before a translation attempt is made or judged.
TERMINAL_STATE_PRECEDENCE: tuple[TerminalState, ...] = (
    TerminalState.SCOPE_DECLINED,
    TerminalState.INSUFFICIENT_CONTEXT,
    TerminalState.CANNOT_EXPRESS,
    TerminalState.MALFUNCTION,
    TerminalState.TRANSLATED,
)

# Which reason codes are valid for each terminal state. Used by contract tests
# and by capability.py to catch programmer error before a result is emitted.
VALID_REASON_CODES_FOR_STATE: dict[TerminalState, tuple[OutcomeReasonCode, ...]] = {
    TerminalState.TRANSLATED: (OutcomeReasonCode.TRANSLATED,),
    TerminalState.CANNOT_EXPRESS: (
        OutcomeReasonCode.UNSUPPORTED_TARGET_TECHNOLOGY,
        OutcomeReasonCode.UNSUPPORTED_FEATURE,
    ),
    TerminalState.INSUFFICIENT_CONTEXT: (
        OutcomeReasonCode.INSUFFICIENT_POLICY_CONTEXT,
        OutcomeReasonCode.INSUFFICIENT_PATTERN_CONTEXT,
    ),
    TerminalState.SCOPE_DECLINED: (
        OutcomeReasonCode.INVALID_INPUT,
        OutcomeReasonCode.POLICY_CONFLICT,
    ),
    TerminalState.MALFUNCTION: (
        OutcomeReasonCode.PROVIDER_FAILURE,
        OutcomeReasonCode.RESULT_ASSEMBLY_FAILURE,
    ),
}


class ResultStatus(str, Enum):
    """Envelope-level status per `api-invocation-surface.md` convention."""

    SUCCEEDED = "succeeded"
    DECLINED = "declined"
    MALFUNCTION = "malfunction"


TERMINAL_STATE_TO_STATUS: dict[TerminalState, ResultStatus] = {
    TerminalState.TRANSLATED: ResultStatus.SUCCEEDED,
    TerminalState.CANNOT_EXPRESS: ResultStatus.DECLINED,
    TerminalState.INSUFFICIENT_CONTEXT: ResultStatus.DECLINED,
    TerminalState.SCOPE_DECLINED: ResultStatus.DECLINED,
    TerminalState.MALFUNCTION: ResultStatus.MALFUNCTION,
}
