from control_translation import capability
from control_translation.contracts import ControlTranslationRequest, TargetContext
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
    pattern = get_fixture_pattern("proven-pattern:CVE-EXAMPLE:waf:3")
    assert pattern is not None
    # edr-s1 adapter only supports process-chain features; this waf pattern's
    # discriminator description does not match, so it should decline.
    # Supply current_policy_snapshot_id explicitly so the missing-context
    # gate does not fire first (edr-s1 has no fixture policy snapshots at
    # all) -- this isolates the cannot-express gate for the test.
    request = ControlTranslationRequest(
        proven_pattern=pattern,
        target_context=TargetContext(
            target_technology="edr-s1",
            target_policy_context_id="edr-context:none",
        ),
        current_policy_snapshot_id="caller-supplied-snapshot:edr:none",
    )
    envelope = capability.invoke(request)
    assert envelope.terminal_state == TerminalState.CANNOT_EXPRESS
    assert envelope.status == "declined"


def test_malfunction_on_provider_failure():
    class ExplodingDoer:
        def propose(self, **kwargs):
            raise RuntimeError("simulated provider outage")

    request = _request("akamai-waf", "akamai-policy:example:rev-17")
    envelope = capability.invoke(request, doer=ExplodingDoer())
    assert envelope.terminal_state == TerminalState.MALFUNCTION
    assert envelope.status == "malfunction"
