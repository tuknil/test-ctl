from pydantic import ValidationError
import pytest

from control_translation.contracts import (
    ControlTranslationRequest,
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
