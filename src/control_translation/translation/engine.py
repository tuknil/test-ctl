"""Translation engine: orchestrates the doer (agent) call and the
deterministic judge gates (syntax validation + conflict detection).

This module returns either a validated `PrimaryCandidate` ready for a
`translated` verdict, or a structured failure reason the capability core
uses to route to `cannot-express` / `insufficient-context` / `malfunction`.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import parse_qsl, quote, quote_plus

from control_translation.adapters.base import TargetAdapter
from control_translation.agents.translation_agent import (
    TranslationDoer,
    TranslationProposal,
)
from control_translation.cancellation import (
    CancellationSignal,
    OperationCancelled,
    check_cancelled,
)
from control_translation.contracts import (
    CandidateArtifact,
    CollateralImpactPrior,
    ImplementsDiscriminator,
    Placement,
    PrimaryCandidate,
    ProofLoopRequestContext,
    ProofLoopTranslationRequirements,
    ProvenMitigationPattern,
)
from control_translation.policy_reader.base import PolicySnapshot
from control_translation.translation import conflict_checker, syntax_validator

logger = logging.getLogger(__name__)


@dataclass
class EngineFailure:
    reason: str  # "unsupported-feature" | "policy-conflict" | "provider-failure"
    detail: str


@dataclass
class EngineSuccess:
    candidate: PrimaryCandidate


EngineResult = EngineFailure | EngineSuccess

_ANCHORED_LITERAL_ARGS_RULE = re.compile(
    r'^\s*SecRule\s+ARGS:([A-Za-z0-9_.-]+)\s+"@rx \^([^"\\\r\n]+)\$"\s+"',
    re.MULTILINE,
)
_REGEX_META = re.compile(r"[.\\^$*+?{}\[\]()|]")
_REQUEST_BODY_RULE = re.compile(r'^\s*SecRule\s+REQUEST_BODY\s+"@rx ', re.MULTILINE)


def translate(
    pattern: ProvenMitigationPattern,
    target_technology: str,
    target_policy_context_id: str,
    adapter: TargetAdapter,
    doer: TranslationDoer,
    snapshot: PolicySnapshot | None,
    translation_requirements: ProofLoopTranslationRequirements | None = None,
    request_context: ProofLoopRequestContext | None = None,
    allow_narrower_translation: bool = True,
    allow_equivalent_translation: bool = True,
    cancellation_signal: CancellationSignal | None = None,
) -> EngineResult:
    # Mechanical gate 1: can this target technology plausibly express the
    # discriminator at all? Cheap check before spending an agent call.
    check_cancelled(cancellation_signal)
    if not adapter.supports_feature(pattern.discriminator_description):
        return EngineFailure(
            reason="unsupported-feature",
            detail=(
                f"{target_technology} adapter does not recognize a supported "
                f"feature for discriminator: {pattern.discriminator_description}"
            ),
        )

    proposal = None
    proposal_from_doer = False
    if target_technology == "akamai-waf" and translation_requirements is None:
        proposal = _hardened_akamai_literal_proposal(pattern)
        if proposal is None:
            proposal = _hardened_akamai_form_body_proposal(pattern, request_context)
    if proposal is None:
        # Doer: propose a candidate artifact (agent output, not yet trusted).
        try:
            check_cancelled(cancellation_signal)
            proposal = doer.propose(
                pattern=pattern,
                target_technology=target_technology,
                artifact_type=adapter.artifact_type,
                snapshot=snapshot,
                translation_requirements=translation_requirements,
                cancellation_signal=cancellation_signal,
            )
            check_cancelled(cancellation_signal)
            proposal_from_doer = True
        except OperationCancelled:
            raise
        except Exception as exc:  # provider/model failure
            logger.exception(
                "Translation provider failed vulnerability_id=%s target_technology=%s",
                pattern.vulnerability_id,
                target_technology,
            )
            return EngineFailure(reason="provider-failure", detail=str(exc))

    policy_failure = _proposal_policy_failure(
        proposal,
        allow_narrower_translation=allow_narrower_translation,
        allow_equivalent_translation=allow_equivalent_translation,
    )
    if policy_failure is not None:
        return policy_failure

    try:
        candidate_content = _normalize_candidate_content(proposal.candidate_content)
    except (TypeError, ValueError) as exc:
        return EngineFailure(reason="provider-failure", detail=str(exc))

    # Judge gate 1: syntax validation (mechanical).
    check_cancelled(cancellation_signal)
    syntax_result = syntax_validator.validate(adapter, candidate_content)
    check_cancelled(cancellation_signal)
    if not syntax_result.valid:
        repair = getattr(doer, "repair", None) if proposal_from_doer else None
        if not callable(repair):
            return EngineFailure(
                reason="unsupported-feature",
                detail="; ".join(syntax_result.errors) or "Candidate failed syntax validation.",
            )
        try:
            check_cancelled(cancellation_signal)
            proposal = TranslationProposal.model_validate(
                repair(
                    pattern=pattern,
                    target_technology=target_technology,
                    artifact_type=adapter.artifact_type,
                    snapshot=snapshot,
                    translation_requirements=translation_requirements,
                    previous_proposal=proposal,
                    validation_errors=list(syntax_result.errors),
                    cancellation_signal=cancellation_signal,
                )
            )
            check_cancelled(cancellation_signal)
            policy_failure = _proposal_policy_failure(
                proposal,
                allow_narrower_translation=allow_narrower_translation,
                allow_equivalent_translation=allow_equivalent_translation,
            )
            if policy_failure is not None:
                return policy_failure
            candidate_content = _normalize_candidate_content(proposal.candidate_content)
        except OperationCancelled:
            raise
        except Exception as exc:
            logger.exception(
                "Translation provider repair failed vulnerability_id=%s target_technology=%s",
                pattern.vulnerability_id,
                target_technology,
            )
            return EngineFailure(reason="provider-failure", detail=str(exc))
        check_cancelled(cancellation_signal)
        syntax_result = syntax_validator.validate(adapter, candidate_content)
        check_cancelled(cancellation_signal)
        if not syntax_result.valid:
            detail = "; ".join(syntax_result.errors) or "Candidate failed syntax validation."
            return EngineFailure(
                reason="provider-failure",
                detail=(
                    "Translation provider produced invalid target candidate syntax "
                    f"after one repair attempt: {detail}"
                ),
            )

    # Judge gate 2: an exact/equivalent Akamai translation must preserve the
    # authoritative original and bypass forms in the correct request component.
    if target_technology == "akamai-waf" and translation_requirements is not None:
        semantic_errors = _akamai_semantic_errors(
            candidate_content,
            proposal.translation_label,
            translation_requirements,
        )
        if semantic_errors:
            return EngineFailure(
                reason="unsupported-feature",
                detail="; ".join(semantic_errors),
            )

    # Judge gate 3: conflict/placement detection (mechanical).
    check_cancelled(cancellation_signal)
    conflicts = conflict_checker.detect_conflicts(
        adapter, candidate_content, snapshot
    )
    check_cancelled(cancellation_signal)

    content_hash = "sha256:" + sha256(candidate_content.encode("utf-8")).hexdigest()

    candidate = PrimaryCandidate(
        candidate_id=f"control-candidate:{pattern.vulnerability_id}:{target_technology}:1",
        target_control_class=pattern.selected_control_class,
        target_technology=target_technology,
        target_policy_context_id=target_policy_context_id,
        candidate_artifact=CandidateArtifact(
            artifact_type=adapter.artifact_type,
            content_ref=candidate_content,
            content_hash=content_hash,
        ),
        implements_discriminator=ImplementsDiscriminator(
            source_discriminator_id=pattern.discriminator_id,
            translation=proposal.translation_label,
            justification=proposal.justification,
            evidence_refs=list(pattern.proof_record_ids),
        ),
        placement=Placement(conflict_notes=conflicts),
        inherited_collateral_impact_prior=CollateralImpactPrior(
            verdict="unknown",
            confidence="unknown",
            basis="Not measured by control-translation; inherited placeholder.",
            measured=False,
        ),
        translation_assumptions=proposal.translation_assumptions,
        limitations=proposal.limitations,
        provenance=list(pattern.proof_record_ids),
    )
    return EngineSuccess(candidate=candidate)


def _normalize_candidate_content(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, (dict, list)):
        try:
            return json.dumps(
                content,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("Translation provider returned non-serializable candidate content.") from exc
    raise TypeError("Translation provider returned unsupported candidate content type.")


def _proposal_policy_failure(
    proposal: TranslationProposal,
    *,
    allow_narrower_translation: bool,
    allow_equivalent_translation: bool,
) -> EngineFailure | None:
    if proposal.translation_label not in ("exact", "equivalent", "narrower"):
        return EngineFailure(
            reason="provider-failure",
            detail=(
                "Doer returned an invalid translation_label: "
                f"{proposal.translation_label!r}"
            ),
        )
    if proposal.translation_label == "equivalent" and not allow_equivalent_translation:
        return EngineFailure(
            reason="unsupported-feature",
            detail="Translation policy does not allow equivalent translations.",
        )
    if proposal.translation_label == "narrower" and not allow_narrower_translation:
        return EngineFailure(
            reason="unsupported-feature",
            detail="Translation policy does not allow narrower translations.",
        )
    return None


def _hardened_akamai_literal_proposal(
    pattern: ProvenMitigationPattern,
) -> TranslationProposal | None:
    match = _ANCHORED_LITERAL_ARGS_RULE.search(pattern.pattern_summary)
    if match is None:
        return None

    parameter, literal = match.groups()
    if literal.startswith("(?:") and literal.endswith(")"):
        literal = literal[3:-1]
    if _REGEX_META.search(literal):
        return None

    encoded_once = quote(literal, safe="")
    values = list(
        dict.fromkeys(
            (
                literal,
                encoded_once,
                quote_plus(literal, safe=""),
                quote(encoded_once, safe=""),
            )
        )
    )
    rule = {
        "name": f"JANUS-{pattern.vulnerability_id}-{parameter}-SQLi",
        "description": (
            f"Blocks the evidenced {parameter} SQL injection value and common "
            "form-encoding variants."
        ),
        "operation": "AND",
        "conditions": [
            {
                "type": "requestMethodMatch",
                "positiveMatch": True,
                "value": ["POST"],
            },
            {
                "type": "argsPostMatch",
                "positiveMatch": True,
                "parameter": parameter,
                "valueCase": False,
                "valueWildcard": False,
                "value": values,
            },
        ],
        "tag": ["JANUS", pattern.vulnerability_id, "SQLi", "virtual-patch"],
    }
    return TranslationProposal(
        candidate_content=rule,
        translation_label="equivalent",
        justification=(
            "Converted the anchored literal ModSecurity named-argument match "
            "into explicit Akamai POST-argument values, including common form "
            "and double-encoding representations."
        ),
        translation_assumptions=[
            "The target Akamai policy supports parameter selection on argsPostMatch.",
            "The custom-rule action is assigned separately; recommended action: deny.",
        ],
        limitations=[
            "The candidate has not been executed in an Akamai tenant.",
            "Coverage is limited to the evidenced literal and generated transport encodings.",
            "No authoritative endpoint path was available, so the rule is not path-scoped.",
        ],
    )


def _hardened_akamai_form_body_proposal(
    pattern: ProvenMitigationPattern,
    request_context: ProofLoopRequestContext | None,
) -> TranslationProposal | None:
    if request_context is None or not _REQUEST_BODY_RULE.search(pattern.pattern_summary):
        return None
    if request_context.method.upper() != "POST":
        return None
    if "application/x-www-form-urlencoded" not in request_context.content_type:
        return None
    pairs = parse_qsl(request_context.body, keep_blank_values=True)
    if not pairs:
        return None

    def serialize(encoder) -> str:
        return "&".join(
            f"{encoder(name, safe='')}={encoder(value, safe='')}"
            for name, value in pairs
        )

    encoded_once = serialize(quote)
    values = list(
        dict.fromkeys(
            (
                request_context.body,
                encoded_once,
                serialize(quote_plus),
                "&".join(
                    f"{quote(quote(name, safe=''), safe='')}="
                    f"{quote(quote(value, safe=''), safe='')}"
                    for name, value in pairs
                ),
            )
        )
    )
    conditions: list[dict] = [
        {
            "type": "requestMethodMatch",
            "positiveMatch": True,
            "value": ["POST"],
        }
    ]
    if request_context.path.startswith("/"):
        conditions.append(
            {
                "type": "pathMatch",
                "positiveMatch": True,
                "value": [request_context.path],
            }
        )
    conditions.append(
        {
            "type": "argsPostMatch",
            "positiveMatch": True,
            "valueCase": False,
            "valueWildcard": False,
            "value": values,
        }
    )
    rule = {
        "name": f"JANUS-{pattern.vulnerability_id}-Form-Body-Mitigation",
        "description": (
            "Blocks the evidenced form body and common transport encodings."
        ),
        "operation": "AND",
        "conditions": conditions,
        "tag": ["JANUS", pattern.vulnerability_id, "form-body", "virtual-patch"],
    }
    return TranslationProposal(
        candidate_content=rule,
        translation_label="narrower",
        justification=(
            "Converted the authoritative proven form body into explicit Akamai "
            "raw, URL-encoded, plus-space, and double-encoded values."
        ),
        translation_assumptions=[
            "The target Akamai policy evaluates argsPostMatch values for form-urlencoded POST bodies.",
            "The custom-rule action is assigned separately; recommended action: deny.",
        ],
        limitations=[
            "The candidate has not been executed in an Akamai tenant.",
            "The explicit values are narrower than arbitrary source regex semantics.",
        ],
    )


def _akamai_semantic_errors(
    candidate_content: str,
    translation_label: str,
    requirements: ProofLoopTranslationRequirements,
) -> list[str]:
    if translation_label not in ("exact", "equivalent"):
        return []

    rule = json.loads(candidate_content)
    conditions = rule["conditions"]
    required_condition_types, component_label = _required_akamai_condition_types(
        requirements
    )
    payload_conditions = [
        condition
        for condition in conditions
        if condition["type"] in required_condition_types
    ]
    payload_values = [
        value
        for condition in payload_conditions
        for value in _condition_values(condition)
    ]
    errors: list[str] = []
    for payload in requirements.required_payloads:
        if not any(_value_covers(value, payload) for value in payload_values):
            errors.append(
                "Exact/equivalent Akamai translation does not preserve required "
                f"{component_label} payload {payload!r} with a documented "
                f"{component_label} condition"
            )

    if requirements.request_path:
        path_values = [
            value
            for condition in conditions
            if condition["type"] == "pathMatch"
            for value in _condition_values(condition)
        ]
        if not any(
            _value_covers(value, requirements.request_path) for value in path_values
        ):
            errors.append(
                "Exact/equivalent Akamai translation does not preserve request path "
                f"{requirements.request_path!r} with a pathMatch condition"
            )
    return errors


def _required_akamai_condition_types(
    requirements: ProofLoopTranslationRequirements,
) -> tuple[set[str], str]:
    location = json.dumps(
        requirements.mutation_location or {}, sort_keys=True
    ).lower()
    if "header" in location:
        return {"requestHeaderValueMatch"}, "request-header"
    if "query" in location:
        return {"uriQueryMatch"}, "query-string"
    if "cookie" in location:
        return {"cookieMatch"}, "cookie"
    if "path" in location:
        return {"pathMatch"}, "request-path"
    return {"argsPostMatch", "argsPostJSONMatch", "argsPostXMLMatch"}, "request-body"


def _value_covers(configured_value: str, required_value: str) -> bool:
    return configured_value.strip("*").lower() == required_value.lower()


def _condition_values(condition: dict) -> list[str]:
    value = condition.get("value")
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []
