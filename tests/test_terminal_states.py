import pytest

from control_translation import capability
from control_translation.contracts import (
    ControlTranslationRequest,
    TargetContext,
    TranslationPolicy,
)
from control_translation.providers.fixtures import get_fixture_pattern
from control_translation.terminal import TerminalState


def _request(target_technology: str, context_id: str) -> ControlTranslationRequest:
    pattern = get_fixture_pattern("proven-pattern:CVE-EXAMPLE:waf:3")
    assert pattern is not None
    return ControlTranslationRequest(
        proven_pattern=pattern,
        target_context=TargetContext(
            target_technology=target_technology,
            target_policy_context_id=context_id,
        ),
    )


def test_translated_happy_path():
    request = _request("akamai-waf", "akamai-policy:example:rev-17")
    envelope = capability.invoke(request)
    assert envelope.terminal_state == TerminalState.TRANSLATED
    assert envelope.status == "succeeded"
    assert envelope.structured_result.primary_candidate is not None


def test_scope_declined_for_unknown_target_technology():
    request = _request("unknown-tech", "some-context")
    envelope = capability.invoke(request)
    assert envelope.terminal_state == TerminalState.SCOPE_DECLINED
    assert envelope.status == "declined"


def test_insufficient_context_when_no_snapshot_available():
    request = _request("akamai-waf", "akamai-policy:does-not-exist")
    envelope = capability.invoke(request)
    assert envelope.terminal_state == TerminalState.INSUFFICIENT_CONTEXT
    assert envelope.status == "declined"


def test_cannot_express_when_adapter_does_not_support_feature():
    pattern = get_fixture_pattern("proven-pattern:CVE-EXAMPLE:edr:1")
    assert pattern is not None
    pattern = pattern.model_copy(
        update={"discriminator_description": "Blocks a registry-only condition."}
    )
    # The selected class and target are compatible, but the EDR adapter does
    # not recognize this discriminator feature, so it cannot express it.
    request = ControlTranslationRequest(
        proven_pattern=pattern,
        target_context=TargetContext(
            target_technology="edr-s1",
            target_policy_context_id="edr-policy:example:rev-1",
        ),
    )
    envelope = capability.invoke(request)
    assert envelope.terminal_state == TerminalState.CANNOT_EXPRESS
    assert envelope.status == "declined"


def test_snapshot_id_cannot_bypass_policy_read():
    request = _request("akamai-waf", "akamai-policy:does-not-exist")
    request.current_policy_snapshot_id = "caller-supplied-snapshot:any"
    envelope = capability.invoke(request)
    assert envelope.terminal_state == TerminalState.INSUFFICIENT_CONTEXT


def test_scope_declined_for_incompatible_control_class():
    request = _request("firewall-generic", "firewall-policy:example:rev-4")
    envelope = capability.invoke(request)
    assert envelope.terminal_state == TerminalState.SCOPE_DECLINED
    assert "not compatible" in envelope.structured_result.outcome_reason.detail


def test_translation_policy_can_disallow_equivalent_result():
    request = _request("akamai-waf", "akamai-policy:example:rev-17")
    request.translation_policy = TranslationPolicy(allow_equivalent_translation=False)
    envelope = capability.invoke(request)
    assert envelope.terminal_state == TerminalState.CANNOT_EXPRESS
    assert "does not allow equivalent" in envelope.structured_result.outcome_reason.detail


@pytest.mark.parametrize(
    ("pattern_id", "technology", "context_id"),
    [
        (
            "proven-pattern:CVE-2021-44228:waf:fixture-1",
            "akamai-waf",
            "akamai-policy:example:rev-17",
        ),
        (
            "proven-pattern:CVE-2021-44228:edr:fixture-1",
            "edr-s1",
            "edr-policy:example:rev-1",
        ),
        (
            "proven-pattern:CVE-2023-27997:firewall:fixture-1",
            "firewall-generic",
            "firewall-policy:dmz:rev-1",
        ),
    ],
)
def test_real_cve_fixtures_translate(pattern_id, technology, context_id):
    pattern = get_fixture_pattern(pattern_id)
    assert pattern is not None
    request = ControlTranslationRequest(
        proven_pattern=pattern,
        target_context=TargetContext(
            target_technology=technology,
            target_policy_context_id=context_id,
        ),
    )
    envelope = capability.invoke(request)
    assert envelope.terminal_state == TerminalState.TRANSLATED
    assert envelope.structured_result.primary_candidate is not None


def test_malfunction_on_provider_failure():
    class ExplodingDoer:
        def propose(self, **kwargs):
            raise RuntimeError("simulated provider outage")

    request = _request("akamai-waf", "akamai-policy:example:rev-17")
    envelope = capability.invoke(request, doer=ExplodingDoer())
    assert envelope.terminal_state == TerminalState.MALFUNCTION
    assert envelope.status == "malfunction"
