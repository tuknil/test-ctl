"""Translation agent: the "doer" role.

Proposes a target-specific candidate artifact (rule/config text) and its
discriminator-translation label from a proven mitigation pattern and target
context. This is agent output only -- it is NOT trusted until it passes
Pydantic validation and the deterministic judge gates in
`translation/syntax_validator.py` and `translation/conflict_checker.py`
(see `translation/engine.py`).

Answer kind: construction (owes: artifact location/content + verification
status -- verification is supplied by the judge gates, not this agent).

Two execution modes:
- fixture (default, offline, deterministic): `FixtureTranslationDoer`
- live (RUN_MODE=live): `LiveTranslationDoer` using a real Pydantic AI agent

Both implement the same `TranslationDoer` protocol and return the same
typed `TranslationProposal` model, so the rest of the capability core does
not care which mode produced the proposal.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, Field

from control_translation.config import Settings
from control_translation.contracts import ProvenMitigationPattern
from control_translation.policy_reader.base import PolicySnapshot


class TranslationProposal(BaseModel):
    """Typed agent output. Never trusted until validated downstream."""

    candidate_content: str = Field(
        description="Proposed rule/config text in the target stack's syntax."
    )
    translation_label: str = Field(
        description="exact | equivalent | narrower"
    )
    justification: str
    translation_assumptions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    answer_kind: str = "construction"


class TranslationDoer(Protocol):
    def propose(
        self,
        pattern: ProvenMitigationPattern,
        target_technology: str,
        artifact_type: str,
        snapshot: PolicySnapshot | None,
    ) -> TranslationProposal:
        ...


class FixtureTranslationDoer:
    """Deterministic offline doer. Builds a candidate mechanically from the
    proven pattern's discriminator description using simple per-target
    templates. Used for default tests and RUN_MODE=fixture."""

    def propose(
        self,
        pattern: ProvenMitigationPattern,
        target_technology: str,
        artifact_type: str,
        snapshot: PolicySnapshot | None,
    ) -> TranslationProposal:
        if target_technology == "akamai-waf":
            content = (
                f'rule "block-{pattern.vulnerability_id.lower()}": '
                f'match header("Content-Type") ~ /(%|\\$)\\{{.*\\}}/ -> block'
            )
            label = "equivalent"
        elif target_technology == "firewall-generic":
            content = (
                f'rule "block-{pattern.vulnerability_id.lower()}": '
                f"deny inbound tcp/8443 from any to any"
            )
            label = "narrower"
        elif target_technology == "edr-s1":
            content = (
                "detect process-chain: web-server -> shell -> network "
                "=> block"
            )
            label = "exact"
        else:
            content = ""
            label = "narrower"

        return TranslationProposal(
            candidate_content=content,
            translation_label=label,
            justification=(
                "Deterministic fixture template derived from the "
                f"discriminator: {pattern.discriminator_description}"
            ),
            translation_assumptions=[
                "Fixture doer: no live policy read, no live model call."
            ],
            limitations=[
                "Candidate is a template, not verified against a real "
                "target tenant."
            ],
        )


class LiveTranslationDoer:
    """Real Pydantic AI agent-backed doer. Requires a configured model
    provider/API key via .env (RUN_MODE=live). Constructed lazily so
    importing this module never requires pydantic_ai model credentials."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._agent = None

    def _build_agent(self):
        from pydantic_ai import Agent

        model_id = f"{self._settings.model_provider}:{self._settings.model_name}"
        return Agent(
            model_id,
            output_type=TranslationProposal,
            system_prompt=(
                "You are a translation doer for a security-control-translation "
                "capability. Given a proven mitigation pattern's discriminator "
                "and a target control technology, propose a candidate rule/config "
                "artifact in that target's syntax. State whether your translation "
                "is exact, equivalent, or narrower relative to the discriminator, "
                "and list any assumptions or limitations. Do not claim the "
                "candidate has been tested or is safe for production -- that is "
                "decided elsewhere. Return only the structured fields requested."
            ),
        )

    def propose(
        self,
        pattern: ProvenMitigationPattern,
        target_technology: str,
        artifact_type: str,
        snapshot: PolicySnapshot | None,
    ) -> TranslationProposal:
        if self._agent is None:
            self._agent = self._build_agent()

        snapshot_desc = (
            "no current policy snapshot available"
            if snapshot is None
            else f"existing rules: {', '.join(snapshot.existing_rule_summaries)}"
        )
        prompt = (
            f"Target technology: {target_technology}\n"
            f"Target artifact type: {artifact_type}\n"
            f"Discriminator: {pattern.discriminator_description}\n"
            f"Pattern summary: {pattern.pattern_summary}\n"
            f"Current policy context: {snapshot_desc}\n"
        )
        result = self._agent.run_sync(prompt)
        return result.output


def build_translation_doer(settings: Settings) -> TranslationDoer:
    """Factory: returns the fixture or live doer based on settings.run_mode."""

    if settings.is_live:
        return LiveTranslationDoer(settings)
    return FixtureTranslationDoer()
