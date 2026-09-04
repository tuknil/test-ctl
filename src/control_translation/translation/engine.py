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
from fnmatch import fnmatchcase
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
    CandidateMetadata,
    CandidateSyntaxProfile,
    CollateralImpactPrior,
    ImplementsDiscriminator,
    JsonBodyFieldFeature,
    Placement,
    PrimaryCandidate,
    ProofLoopRequestContext,
    ProofLoopTranslationRequirements,
    ProvenMitigationPattern,
    RecommendedPolicyBinding,
)
from control_translation.policy_reader.base import PolicySnapshot
from control_translation.translation import conflict_checker, syntax_validator
from control_translation.translation.modsec_akamai import compile_akamai_custom_rule

logger = logging.getLogger(__name__)


@dataclass
class EngineFailure:
    reason: str  # "unsupported-feature" | "policy-conflict" | "provider-failure"
    detail: str
    proposal_source: str = "none"
    llm_invoked: bool = False


@dataclass
class EngineSuccess:
    candidate: PrimaryCandidate
    proposal_source: str
    llm_invoked: bool


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
    check_cancelled(cancellation_signal)

    # Default path for Akamai: derive the custom rule from the authoritative
    # upstream artifact in code. The doer is only reached when no deterministic
    # path can express the proven pattern.
    proposal = None
    proposal_from_doer = False
    proposal_source = "none"
    if target_technology == "akamai-waf":
        proposal, proposal_source = _akamai_deterministic_proposal(
            pattern,
            translation_requirements=translation_requirements,
            request_context=request_context,
        )

    if proposal is None:
        # Mechanical gate: can this target technology plausibly express the
        # discriminator at all? Cheap check before spending an agent call. A
        # deterministically compiled rule has already answered this question,
        # so the keyword gate only guards the doer.
        if not adapter.supports_feature(
            pattern.discriminator_description,
            pattern.json_body_field_feature,
        ):
            return EngineFailure(
                reason="unsupported-feature",
                detail=(
                    f"{target_technology} adapter does not recognize a supported "
                    f"feature for discriminator: {pattern.discriminator_description}"
                ),
            )
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
            proposal_source = "translation-doer"
        except OperationCancelled:
            raise
        except Exception as exc:  # provider/model failure
            logger.exception(
                "Translation provider failed vulnerability_id=%s target_technology=%s",
                pattern.vulnerability_id,
                target_technology,
            )
            return EngineFailure(
                reason="provider-failure",
                detail=str(exc),
                proposal_source="translation-doer",
                llm_invoked=True,
            )

    policy_failure = _proposal_policy_failure(
        proposal,
        allow_narrower_translation=allow_narrower_translation,
        allow_equivalent_translation=allow_equivalent_translation,
    )
    if policy_failure is not None:
        policy_failure.proposal_source = proposal_source
        policy_failure.llm_invoked = proposal_from_doer
        return policy_failure

    try:
        candidate_content = _normalize_candidate_content(proposal.candidate_content)
    except (TypeError, ValueError) as exc:
        return EngineFailure(
            reason="provider-failure",
            detail=str(exc),
            proposal_source=proposal_source,
            llm_invoked=proposal_from_doer,
        )

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
                proposal_source=proposal_source,
                llm_invoked=proposal_from_doer,
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
                policy_failure.proposal_source = proposal_source
                policy_failure.llm_invoked = True
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
            return EngineFailure(
                reason="provider-failure",
                detail=str(exc),
                proposal_source=proposal_source,
                llm_invoked=True,
            )
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
                proposal_source=proposal_source,
                llm_invoked=True,
            )

    if target_technology == "akamai-waf" and pattern.json_body_field_feature:
        semantic_errors = _akamai_json_body_semantic_errors(
            candidate_content,
            pattern.json_body_field_feature,
        )
        if semantic_errors:
            return EngineFailure(
                reason="unsupported-feature",
                detail="; ".join(semantic_errors),
                proposal_source=proposal_source,
                llm_invoked=proposal_from_doer,
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
                proposal_source=proposal_source,
                llm_invoked=proposal_from_doer,
            )

    # Judge gate 3: conflict/placement detection (mechanical).
    check_cancelled(cancellation_signal)
    conflicts = conflict_checker.detect_conflicts(
        adapter, candidate_content, snapshot
    )
    check_cancelled(cancellation_signal)

    content_hash = "sha256:" + sha256(candidate_content.encode("utf-8")).hexdigest()

    candidate = PrimaryCandidate(
        candidate_id=(
            f"control-candidate:{pattern.vulnerability_id}:{target_technology}:"
            f"{content_hash.removeprefix('sha256:')[:16]}"
        ),
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
        candidate_metadata=(
            CandidateMetadata(
                syntax_profile=CandidateSyntaxProfile(
                    id="janus-akamai-like-custom-rule-demo@1",
                    family="akamai-like-custom-rule",
                ),
                recommended_policy_binding=RecommendedPolicyBinding(),
            )
            if target_technology == "akamai-waf"
            else None
        ),
    )
    return EngineSuccess(
        candidate=candidate,
        proposal_source=proposal_source,
        llm_invoked=proposal_from_doer,
    )


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


def _akamai_deterministic_proposal(
    pattern: ProvenMitigationPattern,
    *,
    translation_requirements: ProofLoopTranslationRequirements | None,
    request_context: ProofLoopRequestContext | None,
) -> tuple[TranslationProposal | None, str]:
    """Build an Akamai candidate in code, most authoritative source first.

    1. the JSON request field uniquely corroborated by Mitigation Check;
    2. an anchored literal named-argument rule, hardened with encodings;
    3. the authoritative proven form body from the Mitigation Check request;
    4. general compilation of the proven ModSecurity rule itself.

    Returns `(None, "none")` when the proven pattern needs the doer.
    """
    proposal = _akamai_json_body_field_proposal(pattern)
    if proposal is not None:
        return proposal, "deterministic-json-body-field"
    if translation_requirements is None:
        proposal = _hardened_akamai_literal_proposal(pattern)
        if proposal is not None:
            return proposal, "deterministic-anchored-literal"
        proposal = _hardened_akamai_form_body_proposal(pattern, request_context)
        if proposal is not None:
            return proposal, "deterministic-form-body"
    proposal = compile_akamai_custom_rule(
        pattern,
        translation_requirements=translation_requirements,
    )
    if proposal is not None:
        return proposal, "deterministic-modsec-rule"
    return None, "none"


def _akamai_json_body_field_proposal(
    pattern: ProvenMitigationPattern,
) -> TranslationProposal | None:
    feature = pattern.json_body_field_feature
    if feature is None:
        return None
    parameter = ".".join(feature.field_path)
    condition_value = "*" if feature.value_match == "field-present" else feature.value
    rule = {
        "name": f"JANUS-{pattern.vulnerability_id}-JSON-Body-Field",
        "description": (
            f"Matches the proven JSON request field {parameter}."
        ),
        "operation": "AND",
        "conditions": [
            {
                "type": "requestMethodMatch",
                "positiveMatch": True,
                "value": [feature.method],
            },
            {
                "type": "requestHeaderValueMatch",
                "positiveMatch": True,
                "header": "Content-Type",
                "valueCase": False,
                "valueWildcard": True,
                "value": [f"*{feature.content_type}*"],
            },
            {
                "type": "argsPostJSONMatch",
                "positiveMatch": True,
                "parameter": parameter,
                "valueCase": True,
                "valueWildcard": feature.value_match in {"contains-token", "field-present"},
                "value": [
                    condition_value
                    if feature.value_match == "field-present"
                    else f"*{condition_value}*"
                    if feature.value_match == "contains-token"
                    else condition_value
                ],
            },
        ],
        "tag": ["JANUS", "json-body-field", "virtual-patch"],
    }
    return TranslationProposal(
        candidate_content=rule,
        translation_label=(
            "equivalent"
            if feature.value_match in {"exact", "field-present"}
            else "narrower"
        ),
        justification=(
            "Mapped the uniquely corroborated Mitigation Check JSON field to an "
            "Akamai-like JSON POST-argument condition that preserves the proven "
            "Defense Generation blocking semantics."
        ),
        translation_assumptions=[
            "The target supports dotted JSON field selection on argsPostJSONMatch.",
            "The recommended deny action is assigned at the security-policy binding.",
        ],
        limitations=[
            "This is a shape-validated Akamai-like demo candidate, not tenant-validated configuration.",
            "Operator review and target-specific policy binding are required before deployment.",
        ],
    )


def _akamai_json_body_semantic_errors(
    candidate_content: str,
    feature: JsonBodyFieldFeature,
) -> list[str]:
    rule = json.loads(candidate_content)
    malicious_value = (
        "janus-nonempty-proven-field"
        if feature.value_match == "field-present"
        else feature.value
        if feature.value_match == "exact"
        else f"janus-prefix {feature.value} janus-suffix"
    )
    malicious = _nested_json_value(feature.field_path, malicious_value)
    benign = (
        {}
        if feature.value_match == "field-present"
        else _nested_json_value(feature.field_path, "janus-benign-node-options")
    )
    if not _akamai_json_rule_matches(rule, feature, malicious):
        return ["Akamai-like candidate does not match the proven malicious JSON field value"]
    if _akamai_json_rule_matches(rule, feature, benign):
        return ["Akamai-like candidate also matches a benign JSON field value"]
    return []


def _nested_json_value(path: list[str], value: str) -> dict:
    document: object = value
    for segment in reversed(path):
        document = {segment: document}
    return document  # type: ignore[return-value]


def _akamai_json_rule_matches(
    rule: dict,
    feature: JsonBodyFieldFeature,
    document: dict,
) -> bool:
    if rule.get("operation") != "AND":
        return False
    outcomes: list[bool] = []
    for condition in rule.get("conditions", []):
        condition_type = condition.get("type")
        if condition_type == "requestMethodMatch":
            outcomes.append(feature.method in _condition_values(condition))
        elif condition_type == "requestHeaderValueMatch":
            if str(condition.get("header", "")).lower() != "content-type":
                return False
            outcomes.append(
                any(
                    _wildcard_match(
                        feature.content_type,
                        value,
                        case_sensitive=condition.get("valueCase") is True,
                    )
                    for value in _condition_values(condition)
                )
            )
        elif condition_type == "argsPostJSONMatch":
            if condition.get("parameter") != ".".join(feature.field_path):
                return False
            actual: object = document
            for segment in feature.field_path:
                if not isinstance(actual, dict) or segment not in actual:
                    return False
                actual = actual[segment]
            if not isinstance(actual, str):
                return False
            configured = _condition_values(condition)
            wildcard = condition.get("valueWildcard") is True
            outcomes.append(
                any(
                    _wildcard_match(
                        actual,
                        value,
                        case_sensitive=condition.get("valueCase") is True,
                    )
                    if wildcard
                    else value == actual
                    for value in configured
                )
            )
        else:
            return False
    return bool(outcomes) and all(outcomes)


def _wildcard_match(actual: str, pattern: str, *, case_sensitive: bool) -> bool:
    if not case_sensitive:
        actual = actual.casefold()
        pattern = pattern.casefold()
    return fnmatchcase(actual, pattern)


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
