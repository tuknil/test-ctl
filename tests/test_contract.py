import json
from pathlib import Path

from pydantic import ValidationError
import pytest

from control_translation.contracts import (
    ControlTranslationRequest,
    InvokeRequestEnvelope,
    ProvenMitigationPattern,
    TargetContext,
)
from control_translation.providers.fixtures import get_fixture_pattern


def _valid_request() -> ControlTranslationRequest:
    pattern = get_fixture_pattern("proven-pattern:CVE-EXAMPLE:waf:3")
    assert pattern is not None
    return ControlTranslationRequest(
        proven_pattern=pattern,
        target_context=TargetContext(
            target_technology="akamai-waf",
            target_policy_context_id="akamai-policy:example:rev-17",
        ),
    )


def test_request_accepts_valid_shape():
    request = _valid_request()
    assert request.proven_pattern.vulnerability_id == "CVE-EXAMPLE"
    assert request.target_context.target_technology == "akamai-waf"


def test_request_rejects_malformed_input():
    with pytest.raises(ValidationError):
        ControlTranslationRequest(
            proven_pattern={"proven_pattern_id": "x"},  # missing required fields
            target_context=TargetContext(
                target_technology="akamai-waf",
                target_policy_context_id="akamai-policy:example:rev-17",
            ),
        )


def test_proven_mitigation_pattern_requires_fields():
    with pytest.raises(ValidationError):
        ProvenMitigationPattern(proven_pattern_id="only-id")


def test_proven_mitigation_pattern_requires_both_proof_capabilities():
    with pytest.raises(ValidationError):
        ProvenMitigationPattern(
            proven_pattern_id="proven-pattern:test:waf:1",
            vulnerability_id="CVE-TEST",
            selected_control_class="waf",
            discriminator_id="discriminator:test:1",
            discriminator_description="Suspicious HTTP header value",
            pattern_summary="Block the suspicious HTTP header value.",
            proof_record_ids=[
                "mitigation-check-result:test:1",
                "mitigation-check-result:test:2",
            ],
        )


def _orchestration_envelope() -> dict:
    def upstream(capability, contract_id, state, schema, table, result_id):
        return {
            "capability": capability,
            "contract_id": contract_id,
            "run_id": f"run:{capability}:1",
            "result_id": result_id,
            "terminal_state": state,
            "status": "completed",
            "correlation_id": "corr-production-1",
            "result_ref": {
                "system": "databricks",
                "catalog": "36889_janus_dev",
                "schema": schema,
                "table": table,
                "key": result_id,
            },
            "evidence_refs": [],
        }

    return {
        "contract_id": "control-translation@1.0",
        "request_id": "control-translation-request:production-1",
        "correlation_id": "corr-production-1",
        "subject": {
            "vulnerability_id": "CVE-2026-77392",
            "candidate_id": "candidate:CVE-2026-77392:waf:1",
        },
        "upstream_inputs": [
            upstream(
                "defense-generation",
                "defense-generation@1.0",
                "candidate-produced",
                "defense_generation",
                "defense_generation_results",
                "defense-generation-result:1",
            ),
            upstream(
                "mitigation-check",
                "mitigation-check@1.0",
                "blocked",
                "mitigation-check",
                "mitigation_check",
                "mitigation-check-result:1",
            ),
            upstream(
                "bypass-validation",
                "capability-completion@1.0",
                "no-bypass-found",
                "bypass_validation",
                "bypass_validation_results",
                "bypass-validation-result:1",
            ),
        ],
        "routing_context": {
            "route": "validated",
            "mitigation_check_terminal_state": "blocked",
            "mitigation_check_match": True,
            "bypass_validation_terminal_state": "no-bypass-found",
            "loop_exhausted": False,
            "completed_iterations": 1,
            "max_iterations": 10,
        },
        "provenance": {"caller": "janus-orchestration", "source": "temporal"},
    }


def test_orchestration_envelope_does_not_require_input_and_uses_request_id():
    envelope = InvokeRequestEnvelope.model_validate(_orchestration_envelope())

    assert envelope.input.proven_pattern is None
    assert envelope.idempotency_key == envelope.request_id
    assert envelope.upstream_result_refs is not None
    assert envelope.routing_metadata is not None


def test_orchestration_envelope_rejects_wrong_contract_and_unknown_fields():
    wrong_contract = _orchestration_envelope()
    wrong_contract["contract_id"] = "control-translation@9.9"
    with pytest.raises(ValidationError):
        InvokeRequestEnvelope.model_validate(wrong_contract)

    unknown_field = _orchestration_envelope()
    unknown_field["unexpected"] = True
    with pytest.raises(ValidationError):
        InvokeRequestEnvelope.model_validate(unknown_field)


def test_orchestration_envelope_rejects_correlation_mismatch():
    body = _orchestration_envelope()
    body["upstream_inputs"][1]["correlation_id"] = "corr-different"

    with pytest.raises(ValidationError):
        InvokeRequestEnvelope.model_validate(body)


@pytest.mark.parametrize(
    "contract_id",
    ["capability-completion@1.0", "bypass-validation@1.0"],
)
def test_bypass_completion_contracts_are_explicitly_supported(contract_id):
    body = _orchestration_envelope()
    body["upstream_inputs"][2]["contract_id"] = contract_id

    assert InvokeRequestEnvelope.model_validate(body).upstream_inputs is not None


def test_exhausted_example_is_valid_production_orchestration_command():
    path = (
        Path(__file__).resolve().parents[1]
        / "examples"
        / "request-referenced-exhausted.json"
    )
    envelope = InvokeRequestEnvelope.model_validate(
        json.loads(path.read_text())
    )

    assert envelope.idempotency_key == envelope.request_id
    assert envelope.routing_context is not None
    assert envelope.routing_context.route == "loop-exhausted"
    assert envelope.routing_context.loop_exhausted is True
    assert envelope.routing_context.completed_iterations == 10
    assert envelope.routing_context.max_iterations == 10
    assert envelope.routing_context.bypass_validation_terminal_state == "bypass-found"
