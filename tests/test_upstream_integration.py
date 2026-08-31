from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from control_translation import capability
from control_translation import api as api_module
from control_translation.api import app
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


def test_exhausted_bypass_found_route_translates_with_bypass_evidence():
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
        result={
            **bypass.result,
            "terminal_state": "bypass-found",
            "bypass_counterexample": {
                "counterexample_id": "bypass:example:encoding",
                "sample_ref": "evidence://bypass/example/sample",
                "variant_family": "encoding",
                "observed_behavior": "reached-protected-target",
                "evidence_refs": ["evidence://target/example"],
            },
        },
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
    assert candidate.candidate_artifact.artifact_type == "akamai-waf-rule"
    assert candidate.candidate_artifact.content_ref
    assert any("not bypass-cleared" in item for item in candidate.limitations)
    assert result.structured_result.outcome_reason.code.value == "translated"
    assert result.structured_result.bypass_counterexample is not None
    assert result.structured_result.bypass_counterexample.variant_family == "encoding"
    assert result.inference["llm_invoked"] is False


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


def _temporal_body() -> dict:
    references = _body()["upstream_result_refs"]
    return {
        "contract_id": "control-translation@1.0",
        "request_id": "janus-control-translation-request-v1-1",
        "correlation_id": CORRELATION_ID,
        "subject": {
            "vulnerability_id": VULNERABILITY_ID,
            "candidate_id": CANDIDATE_ID,
        },
        "upstream_inputs": [
            {
                "capability": capability_name,
                "contract_id": contract_id,
                "run_id": run_id,
                "result_id": reference["key"],
                "terminal_state": terminal_state,
                "status": "completed",
                "correlation_id": CORRELATION_ID,
                "result_ref": reference,
            }
            for capability_name, contract_id, run_id, reference, terminal_state in (
                (
                    "defense-generation",
                    "defense-generation@1.0",
                    "defense-run-1",
                    references["defense_generation"],
                    "candidate-produced",
                ),
                (
                    "mitigation-check",
                    "mitigation-check@1.0",
                    "mitigation-run-1",
                    references["mitigation_check"],
                    "blocked",
                ),
                (
                    "bypass-validation",
                    "capability-completion@1.0",
                    "bypass-run-1",
                    references["bypass_validation"],
                    "bypass-found",
                ),
            )
        ],
        "routing_context": {
            "route": "loop-exhausted",
            "mitigation_check_terminal_state": "blocked",
            "mitigation_check_match": True,
            "bypass_validation_terminal_state": "bypass-found",
            "loop_exhausted": True,
            "completed_iterations": 10,
            "max_iterations": 10,
        },
        "provenance": {
            "caller": "janus-orchestration",
            "source": "temporal",
        },
    }


def _temporal_records() -> dict[str, UpstreamRecord]:
    records = _records()
    defense = records["defense-generation-result:defense-1"]
    records[defense.result_id] = UpstreamRecord(
        result_id=defense.result_id,
        terminal_state=defense.terminal_state,
        correlation_id=None,
        subject_record_revision_id=None,
        request={
            "vulnerability_id": VULNERABILITY_ID,
            "selected_control_class": "waf",
            "discriminator": "Block an SQL injection token in the HTTP request body.",
        },
        result={
            "attempt_history": [{"candidate_id": "candidate:historical"}],
            "primary_candidate": defense.result["primary_candidate"],
        },
    )
    mitigation = records["mitigation-check-result:mitigation-1"]
    records[mitigation.result_id] = UpstreamRecord(
        result_id=mitigation.result_id,
        terminal_state=mitigation.terminal_state,
        correlation_id=CORRELATION_ID,
        subject_record_revision_id=None,
        request={},
        result={
            "correlation_id": CORRELATION_ID,
            "terminal_state": "blocked",
            "candidate": {"kind": "waf-rule", "rule_id": "109555"},
        },
    )
    bypass = records["bypass-validation-result:bypass-1"]
    records[bypass.result_id] = UpstreamRecord(
        result_id=bypass.result_id,
        terminal_state="bypass-found",
        correlation_id=CORRELATION_ID,
        subject_record_revision_id=None,
        request={},
        result={
            "correlation_id": CORRELATION_ID,
            "terminal_state": "bypass-found",
            "subject": {
                "vulnerability_id": CANDIDATE_ID,
                "candidate_id": f"candidate:{CANDIDATE_ID}:waf:109555",
            },
            "bypass_counterexample": {
                "counterexample_id": "bypass:bypass-run-1:variant:encoding:1",
                "sample_ref": "evidence://bypass/bypass-run-1/sample",
                "variant_family": "encoding",
                "observed_behavior": "reached-protected-target",
                "evidence_refs": [
                    "evidence://control/bypass-run-1:attempt-2",
                    "evidence://target/bypass-run-1:attempt-2",
                ],
            },
        },
    )
    return records


def test_temporal_envelope_is_normalized_and_translated_after_exhaustion():
    envelope = InvokeRequestEnvelope.model_validate(_temporal_body())

    records = _temporal_records()
    bypass = records["bypass-validation-result:bypass-1"]
    records[bypass.result_id] = UpstreamRecord(
        result_id=bypass.result_id,
        terminal_state=bypass.terminal_state,
        correlation_id=bypass.correlation_id,
        subject_record_revision_id=bypass.subject_record_revision_id,
        request=bypass.request,
        result={
            **bypass.result,
            "bypass_counterexample": {
                **bypass.result["bypass_counterexample"],
                "bypass_variant_or_encoding": "hexadecimal",
                "counterexample_body": "526573656172636865723d27",
                "effective_request": {
                    "method": "POST",
                    "path": "/public/submit.php",
                    "body": "526573656172636865723d27",
                },
                "generator_type": "deterministic",
                "generator_version": "1",
                "mutation_location": {
                    "component": "body",
                    "parameter": "Researcher",
                },
                "original_payload": "Researcher='",
                "payload": "526573656172636865723d27",
                "payload_sha256": "sha256:example",
                "target_observation": {"reached": True},
                "variant_id": "variant:hex:1",
                "waf_observation": {
                    "decision": "allowed",
                    "canonical_forms": ["526573656172636865723d27"],
                },
            },
            "feedback": {
                "bypass_payload": "526573656172636865723d27",
                "bypass_variant_or_encoding": "hexadecimal",
                "constraint_for_next_candidate": "Cover the hexadecimal bypass form.",
                "evidence_refs": ["evidence://feedback/hex"],
                "original_payload": "Researcher='",
            },
        },
    )

    assert envelope.input.proven_pattern is None
    assert envelope.upstream_result_refs is not None
    assert envelope.upstream_result_refs.defense_generation.key.endswith("defense-1")
    assert envelope.routing_metadata is not None
    assert envelope.routing_metadata.loop_exhausted is True
    assert envelope.routing_metadata.completed_iterations == 10
    assert envelope.subject is not None
    assert envelope.subject.candidate_id == CANDIDATE_ID
    assert envelope.idempotency_key == envelope.request_id

    result = capability.invoke_envelope(
        envelope,
        resolver=FakeResolver(records),
        settings=_settings(),
    )

    assert result.terminal_state == TerminalState.TRANSLATED
    qualification = result.structured_result.proof_loop_qualification
    assert qualification is not None
    assert qualification.route == "poc-exhaustion"
    assert qualification.bypass_cleared is False
    candidate = result.structured_result.primary_candidate
    assert candidate is not None
    assert candidate.candidate_artifact.artifact_type == "akamai-waf-rule"
    artifact = json.loads(candidate.candidate_artifact.content_ref)
    condition_types = {condition["type"] for condition in artifact["conditions"]}
    assert condition_types == {"pathMatch", "argsPostMatch"}
    artifact_values = {
        value
        for condition in artifact["conditions"]
        for value in condition["value"]
    }
    assert "Researcher='" in artifact_values
    assert "526573656172636865723d27" in artifact_values
    assert not any("header" in condition for condition in artifact["conditions"])
    assert any("not bypass-cleared" in item for item in candidate.limitations)
    assert result.structured_result.bypass_counterexample is not None
    assert result.request_id == envelope.request_id
    assert result.correlation_id == CORRELATION_ID
    assert result.upstream_result_refs == envelope.upstream_result_refs


def test_temporal_validated_route_translates_without_input_field():
    body = _temporal_body()
    body["upstream_inputs"][2]["terminal_state"] = "no-bypass-found"
    body["routing_context"].update(
        {
            "route": "validated",
            "bypass_validation_terminal_state": "no-bypass-found",
            "loop_exhausted": False,
            "completed_iterations": 1,
        }
    )
    records = _temporal_records()
    bypass = records["bypass-validation-result:bypass-1"]
    records[bypass.result_id] = UpstreamRecord(
        result_id=bypass.result_id,
        terminal_state="no-bypass-found",
        correlation_id=bypass.correlation_id,
        subject_record_revision_id=bypass.subject_record_revision_id,
        request=bypass.request,
        result={**bypass.result, "terminal_state": "no-bypass-found"},
    )

    result = capability.invoke_envelope(
        InvokeRequestEnvelope.model_validate(body),
        resolver=FakeResolver(records),
        settings=_settings(),
    )

    assert result.terminal_state == TerminalState.TRANSLATED
    assert result.request_id == body["request_id"]
    assert result.correlation_id == body["correlation_id"]


def test_temporal_request_id_is_idempotent_at_invoke_endpoint(monkeypatch):
    body = _temporal_body()
    monkeypatch.setattr(
        api_module,
        "_UPSTREAM_RESOLVER",
        FakeResolver(_temporal_records()),
    )
    client = TestClient(app)

    first = client.post("/invoke", json=body)
    second = client.post("/invoke", json=body)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["run_id"] == second.json()["run_id"]
    assert first.json()["request_id"] == body["request_id"]
    assert first.json()["correlation_id"] == body["correlation_id"]
    assert first.json()["terminal_state"] == "translated"
    candidate = first.json()["structured_result"]["primary_candidate"]
    assert candidate is not None
    assert any("not bypass-cleared" in item for item in candidate["limitations"])
    assert (
        first.json()["structured_result"]["bypass_counterexample"][
            "variant_family"
        ]
        == "encoding"
    )


def test_temporal_missing_policy_snapshot_is_typed_decline():
    body = _temporal_body()
    body["upstream_inputs"][2]["terminal_state"] = "no-bypass-found"
    body["routing_context"].update(
        {
            "route": "validated",
            "bypass_validation_terminal_state": "no-bypass-found",
            "loop_exhausted": False,
            "completed_iterations": 1,
        }
    )
    body["input"] = {
        "target_context": {
            "target_technology": "akamai-waf",
            "target_policy_context_id": "akamai-policy:missing",
        }
    }
    records = _temporal_records()
    bypass = records["bypass-validation-result:bypass-1"]
    records[bypass.result_id] = UpstreamRecord(
        result_id=bypass.result_id,
        terminal_state="no-bypass-found",
        correlation_id=bypass.correlation_id,
        subject_record_revision_id=bypass.subject_record_revision_id,
        request=bypass.request,
        result={**bypass.result, "terminal_state": "no-bypass-found"},
    )

    result = capability.invoke_envelope(
        InvokeRequestEnvelope.model_validate(body),
        resolver=FakeResolver(records),
        settings=_settings(),
    )

    assert result.terminal_state == TerminalState.INSUFFICIENT_CONTEXT
    assert result.structured_result.primary_candidate is None


def test_temporal_subject_conflict_returns_insufficient_context():
    body = _temporal_body()
    body["subject"]["candidate_id"] = "candidate:different"

    result = capability.invoke_envelope(
        InvokeRequestEnvelope.model_validate(body),
        resolver=FakeResolver(_temporal_records()),
        settings=_settings(),
    )

    assert result.terminal_state == TerminalState.INSUFFICIENT_CONTEXT
    assert "candidate lineage" in result.structured_result.outcome_reason.detail


def test_temporal_upstream_result_id_must_match_reference():
    body = _temporal_body()
    body["upstream_inputs"][0]["result_id"] = "defense-generation-result:other"

    with pytest.raises(ValidationError):
        InvokeRequestEnvelope.model_validate(body)
