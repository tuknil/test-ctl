"""Resolve and validate authoritative proof-loop records for translation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from control_translation.contracts import (
    DatabricksResultReference,
    ProofLoopQualification,
    ProofLoopRoutingMetadata,
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
    def fetch(self, reference: DatabricksResultReference) -> UpstreamRecord | None: ...


@dataclass(frozen=True)
class ResolvedProofLoop:
    pattern: ProvenMitigationPattern
    references: UpstreamResultReferences
    qualification: ProofLoopQualification


def resolve_proof_loop(
    references: UpstreamResultReferences,
    resolver: UpstreamResultResolver,
    *,
    correlation_id: str | None,
    subject_record_revision_id: str | None,
    routing_metadata: ProofLoopRoutingMetadata,
) -> ResolvedProofLoop:
    """Fetch all three records and enforce proof state and cross-record lineage."""
    if not correlation_id:
        raise UpstreamResolutionError("correlation_id is required for lineage validation")
    if not subject_record_revision_id:
        raise UpstreamResolutionError(
            "subject_record_revision_id is required for lineage validation"
        )

    required_bypass_state = routing_metadata.bypass_validation_terminal_state
    role_refs = (
        ("Defense Generation", references.defense_generation, "candidate-produced"),
        ("Mitigation Check", references.mitigation_check, "blocked"),
        ("Bypass Validation", references.bypass_validation, required_bypass_state),
    )
    records: dict[str, UpstreamRecord] = {}
    for role, reference, required_state in role_refs:
        try:
            record = resolver.fetch(reference)
        except Exception as exc:
            raise UpstreamResolutionError(f"{role} result could not be fetched") from exc
        if record is None:
            raise UpstreamResolutionError(f"{role} result reference was not found")
        if record.result_id != reference.key:
            raise UpstreamResolutionError(f"{role} result ID does not match its reference")
        if record.terminal_state != required_state:
            raise UpstreamResolutionError(
                f"{role} terminal state must be '{required_state}'"
            )
        records[role] = record

    for role, record in records.items():
        record_correlation = _one_value(record.document, "correlation_id")
        record_subject = _one_value(record.document, "subject_record_revision_id")
        if record_correlation != correlation_id:
            raise UpstreamResolutionError(f"{role} correlation lineage could not be validated")
        if record_subject != subject_record_revision_id:
            raise UpstreamResolutionError(f"{role} subject lineage could not be validated")

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
    candidate_id = candidates["Defense Generation"]
    vulnerability_id = vulnerabilities["Defense Generation"]
    mitigation_id = records["Mitigation Check"].result_id
    bypass_id = records["Bypass Validation"].result_id

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
    return ResolvedProofLoop(
        pattern=pattern,
        references=references,
        qualification=qualification,
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
