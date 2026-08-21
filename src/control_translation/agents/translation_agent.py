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

import json
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
            if pattern.vulnerability_id == "CVE-2021-44228":
                header = "user-agent"
                values = ["*${jndi:*"]
                tags = ["JNDI", "Log4Shell", pattern.vulnerability_id]
                label = "narrower"
            else:
                header = "content-type"
                values = ["*%{*", "*${*"]
                tags = ["OGNL", "EL", pattern.vulnerability_id]
                label = "equivalent"
            content = json.dumps(
                {
                    "name": f"block-{pattern.vulnerability_id.lower()}",
                    "description": pattern.pattern_summary,
                    "operation": "AND",
                    "conditions": [
                        {
                            "type": "requestHeaderValueMatch",
                            "positiveMatch": True,
                            "header": header,
                            "valueCase": True,
                            "valueWildcard": True,
                            "value": values,
                        },
                    ],
                    "tag": tags,
                },
                indent=2,
            )
            limitations = [
                "Candidate is a template, not verified against a real Akamai tenant.",
                "Header-only matching can miss encoded or obfuscated variants and other input locations.",
                "This virtual patch does not replace upgrading the vulnerable product.",
                "Action (deny/alert) is assigned separately when the rule is "
                "attached to a security policy; recommended action: deny.",
            ]
        elif target_technology == "firewall-generic":
            if pattern.vulnerability_id == "CVE-2023-27997":
                destination = "fortios-ssl-vpn-gateway"
                service = "tcp-443"
            else:
                destination = "mgmt-server"
                service = "tcp-8443"
            content = (
                f'set rulebase security rules "block-{pattern.vulnerability_id.lower()}" '
                f"from untrust to trust source any destination {destination} "
                f"application any service {service} action deny"
            )
            label = "narrower"
            limitations = [
                "Candidate is a template, not verified against a real PAN-OS tenant.",
                f"Referenced address/service objects ({destination}, {service}) must "
                "exist and the change must be committed before it takes effect.",
                "Network isolation can interrupt legitimate service and does not replace vendor updates.",
            ]
        elif target_technology == "edr-s1":
            if pattern.vulnerability_id == "CVE-2021-44228":
                s1ql = (
                    "EventType = 'Process Creation' AND "
                    "SrcProcName ContainsCIS 'java' AND "
                    "TgtProcName In Contains Anycase "
                    "('sh','bash','cmd.exe','powershell.exe','curl','wget','certutil.exe')"
                )
                severity = "High"
            else:
                s1ql = (
                    "EventType = 'Process Creation' AND "
                    "SrcProcName ContainsCIS 'httpd' AND "
                    "TgtProcName In Contains Anycase ('sh','bash','cmd.exe')"
                )
                severity = "Medium"
            content = json.dumps(
                {
                    "data": {
                        "name": f"detect-{pattern.vulnerability_id.lower()}",
                        "description": pattern.pattern_summary,
                        "severity": severity,
                        "queryType": "events",
                        "queryLang": "2.0",
                        "s1ql": s1ql,
                        "expirationMode": "Permanent",
                        "networkQuarantine": False,
                        "treatAsThreat": "UNDEFINED",
                    },
                    "filter": {"siteIds": ["<SITE_ID>"]},
                },
                indent=2,
            )
            label = "exact"
            limitations = [
                "Candidate is a template, not verified against a real S1 console.",
                "Behavioral detections can produce false positives and do not prove exploit attribution.",
                "Defaults to alert-only (treatAsThreat=UNDEFINED, "
                "networkQuarantine=false); kill/quarantine is an explicit opt-in.",
                "STAR is cloud-only and requires an authenticated console token.",
            ]
        else:
            content = ""
            label = "narrower"
            limitations = [
                "Candidate is a template, not verified against a real target tenant."
            ]

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
            limitations=limitations,
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
                "artifact in that target's real syntax:\n"
                "- akamai-waf: an Akamai Application Security custom-rule JSON "
                "object with 'operation' (AND/OR) and a 'conditions' array; do "
                "NOT embed an action (alert/deny) in the rule body.\n"
                "- firewall-generic: a PAN-OS security rule as a CLI "
                "'set rulebase security rules ...' command or an XML <entry>, "
                "with from/to zones, source, destination, application, service, "
                "and action.\n"
                "- edr-s1: a SentinelOne STAR rule JSON body "
                "(data{name, s1ql, severity, queryLang:'2.0', treatAsThreat}); "
                "default treatAsThreat to 'UNDEFINED' (alert-only) and "
                "networkQuarantine to false unless containment is explicitly "
                "required.\n"
                "State whether your translation is exact, equivalent, or narrower "
                "relative to the discriminator, and list any assumptions or "
                "limitations. Do not claim the candidate has been tested or is "
                "safe for production -- that is decided elsewhere. Return only the "
                "structured fields requested."
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
