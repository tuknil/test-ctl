from __future__ import annotations

import pytest
from pydantic import ValidationError

from control_translation import capability
from control_translation.config import Settings
from control_translation.contracts import InvokeRequestEnvelope
from control_translation.terminal import TerminalState
from control_translation.upstream import UpstreamRecord


CORRELATION_ID = "corr-proof-loop-1"
SUBJECT_REVISION = "canonical-vulnerability-revision:1"
VULNERABILITY_ID = "CVE-2026-77392"
CANDIDATE_ID = "candidate:CVE-2026-77392:waf:abc123"


def _body() -> dict:
    body = {
        "input": {},
        "correlation_id": CORRELATION_ID,
        "subject_record_revision_id": SUBJECT_REVISION,
        "upstream_result_refs": {
            "defense_generation": {
                "system": "databricks",
                "catalog": "36889_janus_dev",
                "schema": "defense_generation",
                "table": "defense_generation_results",
                "key": "defense-generation-result:defense-1",
            },
            "mitigation_check": {
                "system": "databricks",
                "catalog": "36889_janus_dev",
                "schema": "mitigation-check",
                "table": "mitigation_check",
                "key": "mitigation-check-result:mitigation-1",
            },
            "bypass_validation": {
                "system": "databricks",
                "catalog": "36889_janus_dev",
                "schema": "bypass_validation",
                "table": "bypass_validation_results",
                "key": "bypass-validation-result:bypass-1",
            },
        },
    }
    body["routing_metadata"] = {
        "loop_exhausted": False,
        "completed_iterations": 1,
        "max_iterations": 10,
        "bypass_validation_terminal_state": "no-bypass-found",
        "bypass_validation_result_ref": body["upstream_result_refs"][
            "bypass_validation"
        ],
    }
    return body


def _records() -> dict[str, UpstreamRecord]:
    common = {
        "vulnerability_id": VULNERABILITY_ID,
        "candidate_id": CANDIDATE_ID,
        "correlation_id": CORRELATION_ID,
        "subject_record_revision_id": SUBJECT_REVISION,
    }
    return {
        "defense-generation-result:defense-1": UpstreamRecord(
            result_id="defense-generation-result:defense-1",
            terminal_state="candidate-produced",
            correlation_id=CORRELATION_ID,
            subject_record_revision_id=SUBJECT_REVISION,
            request={**common, "selected_control_class": "waf"},
            result={
                **common,
                "primary_candidate": {
                    "candidate_id": CANDIDATE_ID,
                    "selected_control_class": "waf",
                    "discriminator": "Block an SQL injection token in the HTTP request body.",
                    "artifact_content": "SecRule ARGS deny SQL injection",
                },
            },
        ),
        "mitigation-check-result:mitigation-1": UpstreamRecord(
            result_id="mitigation-check-result:mitigation-1",
            terminal_state="blocked",
            correlation_id=CORRELATION_ID,
            subject_record_revision_id=SUBJECT_REVISION,
            request={},
            result={**common, "terminal_state": "blocked"},
        ),
        "bypass-validation-result:bypass-1": UpstreamRecord(
            result_id="bypass-validation-result:bypass-1",
            terminal_state="no-bypass-found",
            correlation_id=CORRELATION_ID,
            subject_record_revision_id=SUBJECT_REVISION,
            request={},
            result={**common, "terminal_state": "no-bypass-found"},
        ),
    }


class FakeResolver:
    def __init__(self, records: dict[str, UpstreamRecord]) -> None:
        self.records = records
        self.fetched: list[str] = []

    def fetch(self, reference):
        self.fetched.append(reference.key)
        return self.records.get(reference.key)


def _settings() -> Settings:
    return Settings(run_mode="fixture", model_provider="none")


def test_reference_invocation_fetches_three_records_and_uses_waf_defaults():
    envelope = InvokeRequestEnvelope.model_validate(_body())
    resolver = FakeResolver(_records())

    result = capability.invoke_envelope(
        envelope,
        resolver=resolver,
        settings=_settings(),
    )

    assert resolver.fetched == [
        "defense-generation-result:defense-1",
        "mitigation-check-result:mitigation-1",
        "bypass-validation-result:bypass-1",
    ]
    assert result.terminal_state == TerminalState.TRANSLATED
    bindings = result.structured_result.input_bindings
    assert bindings.target_technology == "akamai-waf"
    assert bindings.target_policy_context_id == "akamai-policy:example:rev-17"
    assert bindings.configured_poc_defaults_used is True
    assert bindings.proof_record_ids == [
        "mitigation-check-result:mitigation-1",
        "bypass-validation-result:bypass-1",
    ]
    assert result.structured_result.primary_candidate is not None
    assert result.structured_result.primary_candidate.target_technology == "akamai-waf"
    assert result.reference_bundle["defense_generation"]["schema"] == "defense_generation"
    qualification = result.structured_result.proof_loop_qualification
    assert qualification is not None
    assert qualification.route == "validated"
    assert qualification.bypass_cleared is True


def test_caller_target_overrides_defaults():
    body = _body()
    body["input"]["target_context"] = {
        "target_technology": "akamai-waf",
        "target_policy_context_id": "akamai-policy:example:rev-17",
    }

    result = capability.invoke_envelope(
        InvokeRequestEnvelope.model_validate(body),
        resolver=FakeResolver(_records()),
        settings=_settings(),
    )

    assert result.structured_result.input_bindings.configured_poc_defaults_used is False


def test_lineage_mismatch_returns_insufficient_context_without_translation():
    records = _records()
    bypass = records["bypass-validation-result:bypass-1"]
    records["bypass-validation-result:bypass-1"] = UpstreamRecord(
        result_id=bypass.result_id,
        terminal_state=bypass.terminal_state,
        correlation_id="different-correlation",
        subject_record_revision_id=bypass.subject_record_revision_id,
        request=bypass.request,
        result={**bypass.result, "correlation_id": "different-correlation"},
    )

    result = capability.invoke_envelope(
        InvokeRequestEnvelope.model_validate(_body()),
        resolver=FakeResolver(records),
        settings=_settings(),
    )

    assert result.terminal_state == TerminalState.INSUFFICIENT_CONTEXT
    assert result.structured_result.primary_candidate is None
    assert "correlation lineage" in result.structured_result.outcome_reason.detail


def test_missing_record_returns_insufficient_context():
    records = _records()
    del records["mitigation-check-result:mitigation-1"]

    result = capability.invoke_envelope(
        InvokeRequestEnvelope.model_validate(_body()),
        resolver=FakeResolver(records),
        settings=_settings(),
    )

    assert result.terminal_state == TerminalState.INSUFFICIENT_CONTEXT
    assert "was not found" in result.structured_result.outcome_reason.detail


def test_wrong_proof_state_returns_insufficient_context():
    records = _records()
    bypass = records["bypass-validation-result:bypass-1"]
    records["bypass-validation-result:bypass-1"] = UpstreamRecord(
        result_id=bypass.result_id,
        terminal_state="bypass-found",
        correlation_id=bypass.correlation_id,
        subject_record_revision_id=bypass.subject_record_revision_id,
        request=bypass.request,
        result={**bypass.result, "terminal_state": "bypass-found"},
    )

    result = capability.invoke_envelope(
        InvokeRequestEnvelope.model_validate(_body()),
        resolver=FakeResolver(records),
        settings=_settings(),
    )

    assert result.terminal_state == TerminalState.INSUFFICIENT_CONTEXT
    assert "no-bypass-found" in result.structured_result.outcome_reason.detail


def test_exhausted_bypass_found_route_translates_but_is_not_bypass_cleared():
    body = _body()
    body["routing_metadata"].update(
        {
            "loop_exhausted": True,
            "completed_iterations": 10,
            "max_iterations": 10,
            "bypass_validation_terminal_state": "bypass-found",
        }
    )
    records = _records()
    bypass = records["bypass-validation-result:bypass-1"]
    records["bypass-validation-result:bypass-1"] = UpstreamRecord(
        result_id=bypass.result_id,
        terminal_state="bypass-found",
        correlation_id=bypass.correlation_id,
        subject_record_revision_id=bypass.subject_record_revision_id,
        request=bypass.request,
        result={**bypass.result, "terminal_state": "bypass-found"},
    )

    result = capability.invoke_envelope(
        InvokeRequestEnvelope.model_validate(body),
        resolver=FakeResolver(records),
        settings=_settings(),
    )

    assert result.terminal_state == TerminalState.TRANSLATED
    qualification = result.structured_result.proof_loop_qualification
    assert qualification is not None
    assert qualification.route == "poc-exhaustion"
    assert qualification.bypass_cleared is False
    assert qualification.loop_exhausted is True
    assert qualification.completed_iterations == 10
    assert qualification.max_iterations == 10
    assert qualification.bypass_validation_terminal_state == "bypass-found"
    assert result.structured_result.subject.proven_pattern_id.startswith(
        "loop-exhausted-pattern:"
    )
    candidate = result.structured_result.primary_candidate
    assert candidate is not None
    assert any("not bypass-cleared" in item for item in candidate.limitations)
    assert "not bypass-cleared" in result.structured_result.outcome_reason.detail


@pytest.mark.parametrize(
    ("completed", "maximum", "exhausted"),
    [(9, 10, True), (10, 10, False), (10, 11, True)],
)
def test_bypass_found_requires_configured_ten_cycle_exhaustion(
    completed: int, maximum: int, exhausted: bool
):
    body = _body()
    body["routing_metadata"].update(
        {
            "loop_exhausted": exhausted,
            "completed_iterations": completed,
            "max_iterations": maximum,
            "bypass_validation_terminal_state": "bypass-found",
        }
    )

    with pytest.raises(ValidationError):
        InvokeRequestEnvelope.model_validate(body)


def test_routing_bypass_reference_must_match_authoritative_reference():
    body = _body()
    body["routing_metadata"]["bypass_validation_result_ref"] = {
        **body["routing_metadata"]["bypass_validation_result_ref"],
        "key": "bypass-validation-result:different",
    }

    with pytest.raises(ValidationError):
        InvokeRequestEnvelope.model_validate(body)
