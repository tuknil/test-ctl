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
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from pydantic import BaseModel, Field

from control_translation.config import Settings
from control_translation.contracts import (
    ProofLoopTranslationRequirements,
    ProvenMitigationPattern,
)
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
        translation_requirements: ProofLoopTranslationRequirements | None = None,
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
        translation_requirements: ProofLoopTranslationRequirements | None = None,
    ) -> TranslationProposal:
        if target_technology == "akamai-waf":
            if translation_requirements and translation_requirements.required_payloads:
                conditions = []
                if translation_requirements.request_path:
                    conditions.append(
                        {
                            "type": "pathMatch",
                            "positiveMatch": True,
                            "valueCase": False,
                            "valueWildcard": False,
                            "value": [translation_requirements.request_path],
                        }
                    )
                conditions.append(
                    {
                        "type": "argsPostMatch",
                        "positiveMatch": True,
                        "valueCase": False,
                        "valueWildcard": True,
                        "value": list(translation_requirements.required_payloads),
                    }
                )
                content = json.dumps(
                    {
                        "name": f"block-{pattern.vulnerability_id.lower()}",
                        "description": pattern.pattern_summary,
                        "operation": "AND",
                        "conditions": conditions,
                        "tag": ["proof-loop", pattern.vulnerability_id],
                    },
                    indent=2,
                )
                label = "equivalent"
            elif pattern.vulnerability_id == "CVE-2021-44228":
                header = "user-agent"
                values = ["*${jndi:*"]
                tags = ["JNDI", "Log4Shell", pattern.vulnerability_id]
                label = "narrower"
            else:
                header = "content-type"
                values = ["*%{*", "*${*"]
                tags = ["OGNL", "EL", pattern.vulnerability_id]
                label = "equivalent"
            if not (translation_requirements and translation_requirements.required_payloads):
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
                (
                    "The candidate preserves only the authoritative proof-loop "
                    "payload forms and request context supplied to translation."
                    if translation_requirements
                    and translation_requirements.required_payloads
                    else "Header-only matching can miss encoded or obfuscated "
                    "variants and other input locations."
                ),
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

        # AT&T Inference exposes an OpenAI-compatible chat-completions API.
        # A model object is required here (rather than a provider:model string)
        # so Pydantic AI sends requests to the configured internal endpoint.
        if self._settings.is_att_inference:
            if not self._settings.credentials_configured:
                raise ValueError(
                    "AT&T Inference live mode requires ATT_INFERENCE_BASE_URL "
                    "and ATT_INFERENCE_API_KEY."
                )
            from pydantic_ai.models.openai import OpenAIModel
            from pydantic_ai.providers.openai import OpenAIProvider

            model = OpenAIModel(
                self._settings.model_name,
                provider=OpenAIProvider(
                    base_url=self._settings.att_inference_base_url,
                    api_key=self._settings.att_inference_api_key,
                ),
            )
        else:
            model = f"{self._settings.model_provider}:{self._settings.model_name}"

        return Agent(
            model,
            output_type=TranslationProposal,
            system_prompt=(
                "You are a translation doer for a security-control-translation "
                "capability. Given a proven mitigation pattern's discriminator "
                "and a target control technology, propose a candidate rule/config "
                "artifact in that target's real syntax:\n"
                "- akamai-waf: an Akamai Application Security custom-rule JSON "
                "object with 'operation' (AND/OR) and a 'conditions' array; do "
                "NOT embed an action (alert/deny) in the rule body. Use pathMatch "
                "for URI paths and argsPostMatch/argsPostJSONMatch/argsPostXMLMatch "
                "for POST body parameters. Never represent URI, body, or form "
                "parameters as synthetic request headers.\n"
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
        translation_requirements: ProofLoopTranslationRequirements | None = None,
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
            f"Authoritative proof-loop translation requirements: "
            f"{_requirements_json(translation_requirements)}\n"
        )
        result = self._agent.run_sync(prompt)
        return result.output


class AttInferenceTranslationDoer:
    """AT&T Inference doer for its OpenAI-compatible chat-completions API.

    This direct adapter keeps the AT&T live path usable in minimal runtime
    images where the optional ``pydantic-ai`` package is not installed. Its
    output is still parsed into ``TranslationProposal`` and always passes the
    same deterministic syntax and policy-conflict gates as other doers.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def propose(
        self,
        pattern: ProvenMitigationPattern,
        target_technology: str,
        artifact_type: str,
        snapshot: PolicySnapshot | None,
        translation_requirements: ProofLoopTranslationRequirements | None = None,
    ) -> TranslationProposal:
        if not self._settings.credentials_configured:
            raise ValueError(
                "AT&T Inference live mode requires ATT_INFERENCE_BASE_URL "
                "and ATT_INFERENCE_API_KEY."
            )

        snapshot_desc = (
            "no current policy snapshot available"
            if snapshot is None
            else f"existing rules: {', '.join(snapshot.existing_rule_summaries)}"
        )
        system_prompt = (
            "You translate proven security mitigation patterns into one target "
            "control artifact. Return a JSON object only, with exactly these "
            "fields: candidate_content (string), translation_label (exact, "
            "equivalent, or narrower), justification (string), "
            "translation_assumptions (array of strings), limitations (array of "
            "strings), and answer_kind (construction). Do not claim the "
            "candidate is tested or production-safe. "
            "For akamai-waf, candidate_content must be an Akamai custom-rule "
            "JSON string with operation (AND or OR) and conditions (no action). "
            "Use pathMatch for URI paths, argsPostMatch/argsPostJSONMatch/"
            "argsPostXMLMatch for POST body parameters, and "
            "requestHeaderValueMatch only for real request headers. Never invent "
            "Request-URI or Request-Body headers. Each condition needs "
            "positiveMatch (boolean) and a non-empty value string or array. For "
            "firewall-generic, provide a PAN-OS security-rule CLI set command "
            "or XML entry including from/to/source/destination/application/"
            "service/action. For edr-s1, provide SentinelOne STAR rule JSON "
            "with data.name, data.s1ql, data.severity, data.queryLang='2.0', "
            "and data.treatAsThreat; default to alert-only."
        )
        user_prompt = (
            f"Target technology: {target_technology}\n"
            f"Target artifact type: {artifact_type}\n"
            f"Discriminator: {pattern.discriminator_description}\n"
            f"Pattern summary: {pattern.pattern_summary}\n"
            f"Current policy context: {snapshot_desc}\n"
            f"Authoritative proof-loop translation requirements: "
            f"{_requirements_json(translation_requirements)}\n"
        )
        payload = {
            "model": self._settings.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        request = Request(
            f"{self._settings.att_inference_base_url.rstrip('/')}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self._settings.att_inference_api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(
                request, timeout=self._settings.model_request_timeout_seconds
            ) as response:
                response_body = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise RuntimeError(f"AT&T Inference returned HTTP {exc.code}.") from exc
        except URLError as exc:
            raise RuntimeError("Unable to reach AT&T Inference.") from exc

        try:
            content = response_body["choices"][0]["message"]["content"]
            if isinstance(content, list):
                content = "".join(
                    part.get("text", "") for part in content if isinstance(part, dict)
                )
            proposal_data = json.loads(content)
            if isinstance(proposal_data.get("candidate_content"), (dict, list)):
                proposal_data["candidate_content"] = json.dumps(
                    proposal_data["candidate_content"], indent=2
                )
            for field in ("translation_assumptions", "limitations"):
                if isinstance(proposal_data.get(field), str):
                    proposal_data[field] = [proposal_data[field]]

            # A model may provide explanatory text rather than the constrained
            # label. Preserve the conservative label in that case; downstream
            # policy and syntax judges still decide whether it can be emitted.
            label = str(proposal_data.get("translation_label", "")).lower()
            proposal_data["translation_label"] = next(
                (item for item in ("exact", "equivalent", "narrower") if item in label),
                "narrower",
            )
            proposal_data["answer_kind"] = "construction"
            return TranslationProposal.model_validate(proposal_data)
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise RuntimeError(
                "AT&T Inference returned an invalid structured translation response."
            ) from exc


def build_translation_doer(settings: Settings) -> TranslationDoer:
    """Factory: returns the fixture or live doer based on settings.run_mode."""

    if settings.is_live and settings.is_att_inference:
        return AttInferenceTranslationDoer(settings)
    if settings.is_live:
        return LiveTranslationDoer(settings)
    return FixtureTranslationDoer()


def _requirements_json(
    requirements: ProofLoopTranslationRequirements | None,
) -> str:
    if requirements is None:
        return "none"
    return requirements.model_dump_json(exclude_none=True)
