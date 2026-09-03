"""Resolve and validate authoritative proof-loop records for translation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

from control_translation.cancellation import (
    CancellationSignal,
    OperationCancelled,
    check_cancelled,
)
from control_translation.contracts import (
    BypassCounterexample,
    DatabricksResultReference,
    JsonBodyFieldFeature,
    ProofLoopQualification,
    ProofLoopRequestContext,
    ProofLoopRoutingMetadata,
    ProofLoopTranslationRequirements,
    ProvenMitigationPattern,
    UpstreamResultReferences,
)


class UpstreamResolutionError(RuntimeError):
    """A referenced record cannot safely be promoted into translation input."""


@dataclass(frozen=True)
class UpstreamRecord:
    result_id: str
    terminal_state: str
    correlation_id: str | None
    subject_record_revision_id: str | None
    request: dict[str, Any]
    result: dict[str, Any]

    @property
    def document(self) -> dict[str, Any]:
        return {
            "result_id": self.result_id,
            "terminal_state": self.terminal_state,
            "correlation_id": self.correlation_id,
            "subject_record_revision_id": self.subject_record_revision_id,
            "request": self.request,
            "result": self.result,
        }


class UpstreamResultResolver(Protocol):
    def fetch(
        self,
        reference: DatabricksResultReference,
        *,
        cancellation_signal: CancellationSignal | None = None,
    ) -> UpstreamRecord | None: ...


@dataclass(frozen=True)
class ResolvedProofLoop:
    pattern: ProvenMitigationPattern
    references: UpstreamResultReferences
    qualification: ProofLoopQualification
    target_technology: str | None
    target_policy_context_id: str | None
    bypass_counterexample: BypassCounterexample | None
    bypass_evidence_refs: tuple[str, ...]
    translation_requirements: ProofLoopTranslationRequirements | None
    request_context: ProofLoopRequestContext | None


def resolve_proof_loop(
    references: UpstreamResultReferences,
    resolver: UpstreamResultResolver,
    *,
    correlation_id: str | None,
    subject_record_revision_id: str | None,
    routing_metadata: ProofLoopRoutingMetadata,
    expected_vulnerability_id: str | None = None,
    expected_candidate_id: str | None = None,
    cancellation_signal: CancellationSignal | None = None,
) -> ResolvedProofLoop:
    """Fetch all three records and enforce proof state and cross-record lineage."""
    check_cancelled(cancellation_signal)
    if not correlation_id:
        raise UpstreamResolutionError("correlation_id is required for lineage validation")
    has_orchestration_subject = bool(
        expected_vulnerability_id and expected_candidate_id
    )
    if not subject_record_revision_id and not has_orchestration_subject:
        raise UpstreamResolutionError(
            "subject_record_revision_id or an orchestration subject binding is required "
            "for lineage validation"
        )

    required_bypass_state = routing_metadata.bypass_validation_terminal_state
    role_refs = (
        ("Defense Generation", references.defense_generation, "candidate-produced"),
        ("Mitigation Check", references.mitigation_check, "blocked"),
        ("Bypass Validation", references.bypass_validation, required_bypass_state),
    )
    records: dict[str, UpstreamRecord] = {}
    for role, reference, required_state in role_refs:
        check_cancelled(cancellation_signal)
        try:
            record = resolver.fetch(
                reference,
                cancellation_signal=cancellation_signal,
            )
        except (OperationCancelled, UpstreamResolutionError):
            raise
        except Exception as exc:
            raise UpstreamResolutionError(f"{role} result could not be fetched") from exc
        check_cancelled(cancellation_signal)
        if record is None:
            raise UpstreamResolutionError(f"{role} result reference was not found")
        if record.result_id != reference.key:
            raise UpstreamResolutionError(f"{role} result ID does not match its reference")
        if record.terminal_state != required_state:
            raise UpstreamResolutionError(
                f"{role} terminal state must be '{required_state}'"
            )
        _validate_record_identity(role, record)
        records[role] = record

    for role, record in records.items():
        check_cancelled(cancellation_signal)
        record_correlation = _one_value(record.document, "correlation_id")
        record_subject = _one_value(record.document, "subject_record_revision_id")
        if record_correlation is not None and record_correlation != correlation_id:
            raise UpstreamResolutionError(f"{role} correlation lineage could not be validated")
        if record_correlation is None and not has_orchestration_subject:
            raise UpstreamResolutionError(f"{role} correlation lineage could not be validated")
        if (
            subject_record_revision_id
            and record_subject is not None
            and record_subject != subject_record_revision_id
        ):
            raise UpstreamResolutionError(f"{role} subject lineage could not be validated")
        if record_subject is None and not has_orchestration_subject:
            raise UpstreamResolutionError(f"{role} subject lineage could not be validated")

    if has_orchestration_subject:
        vulnerability_id = expected_vulnerability_id or ""
        candidate_id = expected_candidate_id or ""
        for role, record in records.items():
            record_vulnerability = _role_vulnerability_id(role, record)
            record_candidate = _role_candidate_id(role, record)
            if record_vulnerability and record_vulnerability != vulnerability_id:
                raise UpstreamResolutionError(
                    f"{role} vulnerability lineage does not match orchestration subject"
                )
            if record_candidate and record_candidate != candidate_id:
                raise UpstreamResolutionError(
                    f"{role} candidate lineage does not match orchestration subject"
                )
        if _role_vulnerability_id("Defense Generation", records["Defense Generation"]) is None:
            raise UpstreamResolutionError(
                "Defense Generation vulnerability_id is missing"
            )
        if _role_candidate_id("Defense Generation", records["Defense Generation"]) is None:
            raise UpstreamResolutionError("Defense Generation candidate_id is missing")
    else:
        vulnerabilities = {
            role: _required_one_value(record.document, "vulnerability_id", role)
            for role, record in records.items()
        }
        candidates = {
            role: _required_one_value(record.document, "candidate_id", role)
            for role, record in records.items()
        }
        if len(set(vulnerabilities.values())) != 1:
            raise UpstreamResolutionError("upstream vulnerability lineage does not match")
        if len(set(candidates.values())) != 1:
            raise UpstreamResolutionError("upstream candidate lineage does not match")
        vulnerability_id = vulnerabilities["Defense Generation"]
        candidate_id = candidates["Defense Generation"]

    defense = records["Defense Generation"]
    primary_candidate = _required_mapping(
        defense.result.get("primary_candidate"),
        "Defense Generation primary_candidate is missing",
    )
    discriminator = _required_string(
        primary_candidate.get("discriminator")
        or defense.request.get("discriminator"),
        "Defense Generation discriminator context is missing",
    )
    selected_control_class = _required_string(
        primary_candidate.get("selected_control_class")
        or defense.request.get("selected_control_class"),
        "Defense Generation selected control class is missing",
    )
    artifact_content = _required_string(
        primary_candidate.get("artifact_content"),
        "Defense Generation candidate artifact content is missing",
    )
    mitigation_id = records["Mitigation Check"].result_id
    bypass_id = records["Bypass Validation"].result_id
    request_context = _mitigation_request_context(
        records["Mitigation Check"].result
    )
    json_body_field_feature = _json_body_field_feature(
        request_context,
        discriminator=discriminator,
        artifact_content=artifact_content,
    )

    bypass_cleared = required_bypass_state == "no-bypass-found"
    pattern = ProvenMitigationPattern(
        proven_pattern_id=(
            f"proven-pattern:{candidate_id}"
            if bypass_cleared
            else f"loop-exhausted-pattern:{candidate_id}"
        ),
        vulnerability_id=vulnerability_id,
        selected_control_class=selected_control_class,
        discriminator_id=f"discriminator:{candidate_id}",
        discriminator_description=discriminator,
        pattern_summary=artifact_content,
        proof_record_ids=[mitigation_id, bypass_id],
        json_body_field_feature=json_body_field_feature,
    )
    qualification = ProofLoopQualification(
        route="validated" if bypass_cleared else "poc-exhaustion",
        bypass_cleared=bypass_cleared,
        loop_exhausted=routing_metadata.loop_exhausted,
        completed_iterations=routing_metadata.completed_iterations,
        max_iterations=routing_metadata.max_iterations,
        bypass_validation_terminal_state=required_bypass_state,
        bypass_validation_result_ref=routing_metadata.bypass_validation_result_ref,
    )
    bypass_result = records["Bypass Validation"].result
    raw_counterexample = bypass_result.get("bypass_counterexample")
    bypass_counterexample = None
    if raw_counterexample is not None:
        try:
            bypass_counterexample = BypassCounterexample.model_validate(
                raw_counterexample
            )
        except ValueError as exc:
            raise UpstreamResolutionError(
                "Bypass Validation counterexample contract is malformed"
            ) from exc
    bypass_evidence_refs: set[str] = set()
    if bypass_counterexample is not None:
        bypass_evidence_refs.update(bypass_counterexample.evidence_refs)
        bypass_evidence_refs.add(bypass_counterexample.sample_ref)
    feedback = bypass_result.get("feedback")
    if isinstance(feedback, dict):
        evidence_refs = feedback.get("evidence_refs")
        if isinstance(evidence_refs, list):
            bypass_evidence_refs.update(
                item for item in evidence_refs if isinstance(item, str) and item
            )
    translation_requirements = _translation_requirements(
        raw_counterexample,
        feedback,
    )
    check_cancelled(cancellation_signal)

    target_technology = _preferred_string(
        defense.result,
        defense.request,
        key="target_technology",
    )
    target_policy_context_id = _preferred_string(
        defense.result,
        defense.request,
        key="target_policy_context_id",
    )
    return ResolvedProofLoop(
        pattern=pattern,
        references=references,
        qualification=qualification,
        target_technology=target_technology,
        target_policy_context_id=target_policy_context_id,
        bypass_counterexample=bypass_counterexample,
        bypass_evidence_refs=tuple(sorted(bypass_evidence_refs)),
        translation_requirements=translation_requirements,
        request_context=request_context,
    )


def _mitigation_request_context(
    mitigation_result: dict[str, Any],
) -> ProofLoopRequestContext | None:
    test_basis = mitigation_result.get("test_basis")
    if not isinstance(test_basis, dict):
        return None
    request = test_basis.get("request")
    if not isinstance(request, dict):
        return None
    method = request.get("method")
    path = request.get("path")
    body = request.get("body")
    headers = request.get("headers") or {}
    if not all(isinstance(value, str) and value for value in (method, path, body)):
        return None
    if not isinstance(headers, dict) or not all(
        isinstance(name, str) and isinstance(value, str)
        for name, value in headers.items()
    ):
        return None
    return ProofLoopRequestContext(
        method=method,
        path=path,
        headers=headers,
        body=body,
    )


_MAX_JSON_BODY_BYTES = 64 * 1024
_MAX_JSON_DEPTH = 12
_MAX_JSON_LEAVES = 256
_MAX_JSON_NODES = 1024
_CORROBORATION_TOKEN = re.compile(
    r"--[A-Za-z0-9_-]{2,64}|[A-Za-z0-9][A-Za-z0-9_.:+/-]{2,127}"
)


def _json_body_field_feature(
    request_context: ProofLoopRequestContext | None,
    *,
    discriminator: str,
    artifact_content: str,
) -> JsonBodyFieldFeature | None:
    """Safely derive one DG-corroborated scalar JSON request field."""
    if request_context is None or request_context.method.strip().upper() != "POST":
        return None
    base_media_type = request_context.content_type.split(";", 1)[0].strip().lower()
    if base_media_type != "application/json":
        return None
    if len(request_context.body.encode("utf-8")) > _MAX_JSON_BODY_BYTES:
        return None
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON constant: {value}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object key: {key}")
            result[key] = value
        return result

    try:
        document = json.loads(
            request_context.body,
            parse_constant=reject_constant,
            object_pairs_hook=unique_object,
        )
    except (TypeError, ValueError, RecursionError):
        return None
    if not isinstance(document, dict):
        return None

    leaves: list[tuple[tuple[str, ...], str]] = []
    nodes_visited = 0
    traversal_exceeded = False

    def visit(value: Any, path: tuple[str, ...], depth: int) -> None:
        nonlocal nodes_visited, traversal_exceeded
        nodes_visited += 1
        if nodes_visited > _MAX_JSON_NODES:
            traversal_exceeded = True
            return
        if depth > _MAX_JSON_DEPTH:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                if not isinstance(key, str) or not re.fullmatch(
                    r"[A-Za-z0-9_-]{1,128}", key
                ):
                    continue
                visit(child, (*path, key), depth + 1)
                if traversal_exceeded:
                    return
            return
        if isinstance(value, list):
            return
        if isinstance(value, str) and value.strip() and len(value) <= 4096:
            leaves.append((path, value))
            if len(leaves) > _MAX_JSON_LEAVES:
                traversal_exceeded = True

    visit(document, (), 0)
    if traversal_exceeded or not leaves:
        return None

    folded_discriminator = discriminator.casefold()
    evidence = (folded_discriminator, artifact_content.casefold())
    corroborated: list[tuple[tuple[str, ...], str, str]] = []
    for path, value in leaves:
        dotted_path = ".".join(path).casefold()
        terminal = path[-1].casefold()
        if not all(
            _evidence_mentions_path(source, dotted_path, terminal)
            for source in evidence
        ):
            continue
        folded_value = value.casefold()
        if all(folded_value in source for source in evidence):
            corroborated.append((path, value, "exact"))
            continue
        tokens = {
            token.casefold(): token
            for token in _CORROBORATION_TOKEN.findall(value)
            if token.strip()
        }
        shared_tokens = sorted(
            folded for folded in tokens if all(folded in source for source in evidence)
        )
        if len(shared_tokens) == 1:
            corroborated.append(
                (path, tokens[shared_tokens[0]], "contains-token")
            )
            continue
        if _artifact_blocks_json_field_presence(artifact_content, path[-1]):
            corroborated.append((path, "*", "field-present"))

    if len(corroborated) != 1:
        return None
    path, value, value_match = corroborated[0]
    return JsonBodyFieldFeature(
        method="POST",
        content_type="application/json",
        field_path=list(path),
        value=value,
        value_match=value_match,
    )


def _artifact_blocks_json_field_presence(artifact_content: str, field: str) -> bool:
    field_pattern = re.compile(
        rf"(?<![A-Za-z0-9_-]){re.escape(field)}(?![A-Za-z0-9_-])",
        re.IGNORECASE,
    )
    request_body_rx = re.compile(
        r'^\s*SecRule\s+REQUEST_BODY\s+"@rx\s+((?:\\.|[^"\\])*)"\s+"',
        re.IGNORECASE,
    )
    for line in artifact_content.splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = request_body_rx.match(line)
        if match is None:
            continue
        expression = match.group(1)
        if field_pattern.search(expression) is None:
            continue
        remainder = expression.replace(r"\b", "")
        remainder = field_pattern.sub("", remainder)
        remainder = remainder.replace(r'\"', "").replace("'", "")
        remainder = re.sub(r"[\s()?:|]+", "", remainder)
        if remainder == "":
            return True
    return False


def _evidence_mentions_path(source: str, dotted_path: str, terminal: str) -> bool:
    if dotted_path in source:
        return True
    return re.search(
        rf"(?<![A-Za-z0-9_-]){re.escape(terminal)}(?![A-Za-z0-9_-])",
        source,
    ) is not None


def _translation_requirements(
    raw_counterexample: Any,
    feedback: Any,
) -> ProofLoopTranslationRequirements | None:
    counterexample = raw_counterexample if isinstance(raw_counterexample, dict) else {}
    feedback_record = feedback if isinstance(feedback, dict) else {}
    waf_observation = counterexample.get("waf_observation")
    canonical_forms: list[str] = []
    if isinstance(waf_observation, dict):
        raw_forms = waf_observation.get("canonical_forms")
        if isinstance(raw_forms, list):
            canonical_forms = [
                item for item in raw_forms if isinstance(item, str) and item
            ]

    requirements = ProofLoopTranslationRequirements(
        original_payload=_preferred_nonempty_string(
            feedback_record.get("original_payload"),
            counterexample.get("original_payload"),
        ),
        bypass_payload=_preferred_nonempty_string(
            feedback_record.get("bypass_payload"),
            counterexample.get("payload"),
            feedback_record.get("counterexample_body"),
            counterexample.get("counterexample_body"),
        ),
        bypass_variant_or_encoding=_preferred_nonempty_string(
            feedback_record.get("bypass_variant_or_encoding"),
            counterexample.get("bypass_variant_or_encoding"),
            counterexample.get("variant_family"),
        ),
        constraint_for_next_candidate=_preferred_nonempty_string(
            feedback_record.get("constraint_for_next_candidate"),
            feedback_record.get("do_not_repeat"),
        ),
        post_waf_canonical_forms=canonical_forms,
        effective_request=(
            counterexample.get("effective_request")
            if isinstance(counterexample.get("effective_request"), dict)
            else None
        ),
        mutation_location=(
            counterexample.get("mutation_location")
            if isinstance(counterexample.get("mutation_location"), dict)
            else None
        ),
    )
    if not any(
        (
            requirements.required_payloads,
            requirements.bypass_variant_or_encoding,
            requirements.constraint_for_next_candidate,
            requirements.effective_request,
            requirements.mutation_location,
        )
    ):
        return None
    return requirements


def _preferred_nonempty_string(*values: Any) -> str | None:
    return next(
        (value for value in values if isinstance(value, str) and value.strip()),
        None,
    )


def decode_json_object(value: Any, label: str) -> dict[str, Any]:
    """Decode a Databricks TO_JSON cell and reject non-object payloads."""
    if value is None:
        return {}
    try:
        decoded = json.loads(value) if isinstance(value, str) else value
    except (TypeError, ValueError) as exc:
        raise UpstreamResolutionError(f"{label} is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise UpstreamResolutionError(f"{label} must be a JSON object")
    return decoded


def _required_mapping(value: Any, message: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise UpstreamResolutionError(message)
    return value


def _required_string(value: Any, message: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise UpstreamResolutionError(message)
    return value


def _required_one_value(document: Any, key: str, role: str) -> str:
    value = _one_value(document, key)
    if value is None:
        raise UpstreamResolutionError(f"{role} {key} is missing or ambiguous")
    return value


def _one_value(document: Any, key: str) -> str | None:
    values: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                if child_key == key and isinstance(child_value, str) and child_value:
                    values.add(child_value)
                visit(child_value)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(document)
    return next(iter(values)) if len(values) == 1 else None


def _role_vulnerability_id(role: str, record: UpstreamRecord) -> str | None:
    """Extract canonical vulnerability lineage without mistaking candidate IDs."""
    if role == "Defense Generation":
        primary = record.result.get("primary_candidate")
        if isinstance(primary, dict):
            value = primary.get("vulnerability_id")
            if isinstance(value, str) and value:
                return value
        value = record.request.get("vulnerability_id")
        if isinstance(value, str) and value:
            return value
    if role == "Bypass Validation":
        subject = record.result.get("subject")
        if isinstance(subject, dict):
            value = subject.get("vulnerability_id")
            if isinstance(value, str) and value.startswith("CVE-"):
                return value
        return None
    return _one_value(record.document, "vulnerability_id")


def _role_candidate_id(role: str, record: UpstreamRecord) -> str | None:
    """Extract the selected source candidate rather than history or test variants."""
    if role == "Defense Generation":
        primary = record.result.get("primary_candidate")
        if isinstance(primary, dict):
            value = primary.get("candidate_id")
            if isinstance(value, str) and value:
                return value
        return None
    if role == "Bypass Validation":
        subject = record.result.get("subject")
        if isinstance(subject, dict):
            source = subject.get("source_candidate_id")
            if isinstance(source, str) and source:
                return source
            # bypass-validation@1.0 currently places the source Defense
            # candidate in vulnerability_id and the generated test variant in
            # candidate_id. Treat only the former as source lineage.
            legacy_source = subject.get("vulnerability_id")
            if isinstance(legacy_source, str) and legacy_source.startswith("candidate:"):
                return legacy_source
        return None
    return _one_value(record.document, "candidate_id")


def _validate_record_identity(role: str, record: UpstreamRecord) -> None:
    """Validate producer identity when the canonical result exposes it."""
    expected = {
        "Defense Generation": (
            "defense-generation",
            {"defense-generation@1.0", "defense-generation-result@1.0"},
        ),
        "Mitigation Check": (
            "mitigation-check",
            {"mitigation-check@1.0"},
        ),
        "Bypass Validation": (
            "bypass-validation",
            {"bypass-validation@1.0"},
        ),
    }
    expected_capability, accepted_contracts = expected[role]
    capability = record.result.get("capability")
    if capability is not None and capability != expected_capability:
        raise UpstreamResolutionError(f"{role} capability identity is invalid")
    contract_id = record.result.get("contract_id")
    if contract_id is not None and contract_id not in accepted_contracts:
        raise UpstreamResolutionError(f"{role} result contract is unsupported")


def _preferred_string(*documents: Any, key: str) -> str | None:
    for document in documents:
        if not isinstance(document, dict):
            continue
        direct = document.get(key)
        if isinstance(direct, str) and direct:
            return direct
        primary = document.get("primary_candidate")
        if isinstance(primary, dict):
            nested = primary.get(key)
            if isinstance(nested, str) and nested:
                return nested
        target = document.get("target_context")
        if isinstance(target, dict):
            nested = target.get(key)
            if isinstance(nested, str) and nested:
                return nested
    return None
