import json

import pytest

from control_translation import capability
from control_translation.agents.translation_agent import TranslationProposal
from control_translation.contracts import (
    ControlTranslationRequest,
    JsonBodyFieldFeature,
    ProofLoopRequestContext,
    ProofLoopTranslationRequirements,
    ProvenMitigationPattern,
    TargetContext,
    TranslationPolicy,
)
from control_translation.providers.fixtures import get_fixture_pattern
from control_translation.terminal import OutcomeReasonCode, TerminalState
from control_translation.translation.engine import _akamai_json_body_semantic_errors


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
    """CFS: a valid target outside configured coverage is scope-declined.

    cannot-express is reserved for a target that cannot represent the pattern,
    which the adapter decides further down.
    """
    envelope = capability.invoke(_request("unknown-tech", "some-context"))

    assert envelope.terminal_state == TerminalState.SCOPE_DECLINED
    assert envelope.status == "declined"
    reason = envelope.structured_result.outcome_reason
    assert reason.code == OutcomeReasonCode.INVALID_INPUT
    # The detail still names what this deployment does carry.
    assert "unknown-tech" in reason.detail
    for supported in ("akamai-waf", "firewall-generic", "edr-s1"):
        assert supported in reason.detail
    assert envelope.structured_result.primary_candidate is None


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


class StaticAkamaiDoer:
    def __init__(self, content: dict) -> None:
        self.content = content

    def propose(self, **kwargs):
        return TranslationProposal(
            candidate_content=json.dumps(self.content),
            translation_label="equivalent",
            justification="Test translation.",
        )


class RepairingAkamaiDoer:
    def __init__(self, repaired_content: object) -> None:
        self.repaired_content = repaired_content
        self.propose_calls = 0
        self.repair_calls = 0

    def propose(self, **kwargs):
        self.propose_calls += 1
        return TranslationProposal(
            candidate_content=r'{"name":"broken","operation":"AND","conditions":[{"type":"argsPostMatch","positiveMatch":true,"value":["\s+"]}]}',
            translation_label="narrower",
            justification="Initial malformed provider candidate.",
        )

    def repair(self, **kwargs):
        self.repair_calls += 1
        return TranslationProposal(
            candidate_content=self.repaired_content,
            translation_label="narrower",
            justification="Repaired provider candidate.",
        )


def _non_deterministic_akamai_request() -> ControlTranslationRequest:
    """A proven rule the deterministic Akamai path declines, so the doer runs.

    Counted repetition (`\\s{2,}`) has no Akamai wildcard equivalent, so
    `modsec_akamai` refuses to guess and the request reaches the doer.
    """
    request = _request("akamai-waf", "akamai-policy:example:rev-17")
    pattern = request.proven_pattern.model_copy(
        update={
            "pattern_summary": (
                "SecRule ARGS:username \"@rx ^test'\\s{2,}OR"
                "(?:\\s|\\+)+'1'='1$\""
            )
        }
    )
    return request.model_copy(update={"proven_pattern": pattern})


def test_structured_akamai_candidate_serializes_regex_once() -> None:
    regex = r"(?i)(?:'\s+OR\s+'1'='1|%27\s*(?:OR|%4f%52|%4F%52)\s*%271%27%3[dD]%271)"
    content = {
        "name": "cve-2026-77392",
        "operation": "AND",
        "conditions": [
            {
                "type": "argsPostMatch",
                "positiveMatch": True,
                "value": [regex],
            }
        ],
    }
    doer = RepairingAkamaiDoer(content)

    envelope = capability.invoke(_non_deterministic_akamai_request(), doer=doer)

    assert envelope.terminal_state == TerminalState.TRANSLATED
    assert doer.propose_calls == 1
    assert doer.repair_calls == 1
    candidate = envelope.structured_result.primary_candidate
    assert candidate is not None
    decoded = json.loads(candidate.candidate_artifact.content_ref)
    assert decoded["conditions"][0]["value"] == [regex]


def test_exhausted_candidate_syntax_repair_is_provider_malfunction() -> None:
    doer = RepairingAkamaiDoer(r'{"conditions":["\s+"]}')

    envelope = capability.invoke(_non_deterministic_akamai_request(), doer=doer)

    assert doer.propose_calls == 1
    assert doer.repair_calls == 1
    assert envelope.terminal_state == TerminalState.MALFUNCTION
    assert envelope.status == "malfunction"
    assert envelope.structured_result.outcome_reason.code == "provider-failure"
    assert "after one repair attempt" in envelope.structured_result.outcome_reason.detail


def _bypass_requirements() -> ProofLoopTranslationRequirements:
    return ProofLoopTranslationRequirements(
        original_payload="Researcher='",
        bypass_payload="526573656172636865723d27",
        bypass_variant_or_encoding="hexadecimal",
        constraint_for_next_candidate="Cover the hexadecimal bypass form.",
        post_waf_canonical_forms=["Researcher%253D%2527", "Researcher='"],
        effective_request={
            "method": "POST",
            "path": "/public/submit.php",
            "body": "526573656172636865723d27",
        },
        mutation_location={"component": "body", "parameter": "Researcher"},
    )


def test_exact_akamai_translation_rejects_missing_bypass_coverage():
    doer = StaticAkamaiDoer(
        {
            "name": "incomplete",
            "operation": "AND",
            "conditions": [
                {
                    "type": "pathMatch",
                    "positiveMatch": True,
                    "value": ["/public/submit.php"],
                },
                {
                    "type": "argsPostMatch",
                    "positiveMatch": True,
                    "value": ["Researcher='"],
                },
            ],
        }
    )

    envelope = capability.invoke(
        _request("akamai-waf", "akamai-policy:example:rev-17"),
        doer=doer,
        translation_requirements=_bypass_requirements(),
    )

    assert envelope.terminal_state == TerminalState.CANNOT_EXPRESS
    assert "526573656172636865723d27" in envelope.structured_result.outcome_reason.detail


def test_exact_akamai_translation_accepts_path_and_body_payload_forms():
    doer = StaticAkamaiDoer(
        {
            "name": "bypass-aware",
            "operation": "AND",
            "conditions": [
                {
                    "type": "pathMatch",
                    "positiveMatch": True,
                    "value": ["/public/submit.php"],
                },
                {
                    "type": "argsPostMatch",
                    "positiveMatch": True,
                    "value": [
                        "Researcher='",
                        "Researcher%253D%2527",
                        "526573656172636865723d27",
                    ],
                },
            ],
        }
    )

    envelope = capability.invoke(
        _request("akamai-waf", "akamai-policy:example:rev-17"),
        doer=doer,
        translation_requirements=_bypass_requirements(),
    )

    assert envelope.terminal_state == TerminalState.TRANSLATED


@pytest.mark.parametrize(
    "source_regex",
    ["^test' OR '1'='1$", "^(?:test' OR '1'='1)$"],
)
def test_anchored_literal_args_rule_is_hardened_deterministically_for_akamai(
    source_regex: str,
):
    class UnexpectedDoer:
        def propose(self, **kwargs):
            raise AssertionError("anchored literal translation must be deterministic")

    pattern = ProvenMitigationPattern(
        proven_pattern_id="proven-pattern:candidate:CVE-2026-77392:waf:test",
        vulnerability_id="CVE-2026-77392",
        selected_control_class="waf",
        discriminator_id="discriminator:test",
        discriminator_description="Block SQL injection in a request parameter.",
        pattern_summary=(
            f'SecRule ARGS:username "@rx {source_regex}" '
            '"id:153101,phase:2,deny,status:403,log"'
        ),
        proof_record_ids=[
            "mitigation-check-result:test",
            "bypass-validation-result:test",
        ],
    )
    request = ControlTranslationRequest(
        proven_pattern=pattern,
        target_context=TargetContext(
            target_technology="akamai-waf",
            target_policy_context_id="akamai-policy:example:rev-17",
        ),
    )

    envelope = capability.invoke(request, doer=UnexpectedDoer())

    assert envelope.terminal_state == TerminalState.TRANSLATED
    candidate = envelope.structured_result.primary_candidate
    assert candidate is not None
    assert candidate.implements_discriminator.translation == "equivalent"
    artifact = json.loads(candidate.candidate_artifact.content_ref)
    assert artifact == {
        "name": "JANUS-CVE-2026-77392-username-SQLi",
        "description": (
            "Blocks the evidenced username SQL injection value and common "
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
                "parameter": "username",
                "valueCase": False,
                "valueWildcard": False,
                "value": [
                    "test' OR '1'='1",
                    "test%27%20OR%20%271%27%3D%271",
                    "test%27+OR+%271%27%3D%271",
                    "test%2527%2520OR%2520%25271%2527%253D%25271",
                ],
            },
        ],
        "tag": ["JANUS", "CVE-2026-77392", "SQLi", "virtual-patch"],
    }


def test_request_body_form_rule_is_hardened_from_authoritative_request_context():
    class UnexpectedDoer:
        def propose(self, **kwargs):
            raise AssertionError("proven form-body translation must be deterministic")

    pattern = ProvenMitigationPattern(
        proven_pattern_id="proven-pattern:candidate:CVE-2026-77392:waf:body",
        vulnerability_id="CVE-2026-77392",
        selected_control_class="waf",
        discriminator_id="discriminator:body",
        discriminator_description="Block a malicious form request body.",
        pattern_summary=(
            'SecRule REQUEST_BODY "@rx person(?:\\\\[|%5B)0.*malicious" '
            '"id:144801,phase:2,deny,status:403,log"'
        ),
        proof_record_ids=[
            "mitigation-check-result:body",
            "bypass-validation-result:body",
        ],
    )
    request = ControlTranslationRequest(
        proven_pattern=pattern,
        target_context=TargetContext(
            target_technology="akamai-waf",
            target_policy_context_id="akamai-policy:example:rev-17",
        ),
    )
    request_context = ProofLoopRequestContext(
        method="POST",
        path="/public/submit.php",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body="person[0][]=malicious",
    )

    envelope = capability.invoke(
        request,
        doer=UnexpectedDoer(),
        request_context=request_context,
    )

    assert envelope.terminal_state == TerminalState.TRANSLATED
    candidate = envelope.structured_result.primary_candidate
    assert candidate is not None
    assert candidate.implements_discriminator.translation == "narrower"
    artifact = json.loads(candidate.candidate_artifact.content_ref)
    assert artifact["name"] == "JANUS-CVE-2026-77392-Form-Body-Mitigation"
    assert artifact["conditions"] == [
        {
            "type": "requestMethodMatch",
            "positiveMatch": True,
            "value": ["POST"],
        },
        {
            "type": "pathMatch",
            "positiveMatch": True,
            "value": ["/public/submit.php"],
        },
        {
            "type": "argsPostMatch",
            "positiveMatch": True,
            "valueCase": False,
            "valueWildcard": False,
            "value": [
                "person[0][]=malicious",
                "person%5B0%5D%5B%5D=malicious",
                "person%255B0%255D%255B%255D=malicious",
            ],
        },
    ]


@pytest.mark.parametrize("run_mode", ["fixture", "live"])
def test_typed_json_body_candidate_is_deterministic_and_review_only(run_mode: str):
    class UnexpectedDoer:
        def propose(self, **kwargs):
            raise AssertionError("typed JSON translation must bypass the doer")

    pattern = ProvenMitigationPattern(
        proven_pattern_id="proven-pattern:candidate:generic-json",
        vulnerability_id="CVE-EXAMPLE",
        selected_control_class="waf",
        discriminator_id="discriminator:generic-json",
        discriminator_description="Opaque producer prose without adapter keywords.",
        pattern_summary='SecRule REQUEST_BODY "@rx node_options.*--require"',
        proof_record_ids=[
            "mitigation-check-result:generic-json",
            "bypass-validation-result:generic-json",
        ],
        json_body_field_feature=JsonBodyFieldFeature(
            method="POST",
            content_type="application/json",
            field_path=["env", "node_options"],
            value="--require",
            value_match="contains-token",
        ),
    )
    request = ControlTranslationRequest(
        proven_pattern=pattern,
        target_context=TargetContext(
            target_technology="akamai-waf",
            target_policy_context_id="akamai-policy:example:rev-17",
        ),
    )

    envelope = capability.invoke(
        request,
        settings=capability.Settings(run_mode=run_mode, model_provider="att"),
        doer=UnexpectedDoer(),
    )

    assert envelope.terminal_state == TerminalState.TRANSLATED
    assert envelope.inference["proposal_source"] == "deterministic-json-body-field"
    assert envelope.inference["llm_invoked"] is False
    candidate = envelope.structured_result.primary_candidate
    assert candidate is not None
    artifact = json.loads(candidate.candidate_artifact.content_ref)
    assert artifact["operation"] == "AND"
    assert {condition["type"] for condition in artifact["conditions"]} == {
        "requestMethodMatch",
        "requestHeaderValueMatch",
        "argsPostJSONMatch",
    }
    header_condition = next(
        condition
        for condition in artifact["conditions"]
        if condition["type"] == "requestHeaderValueMatch"
    )
    assert header_condition["value"] == ["*application/json*"]
    json_condition = next(
        condition
        for condition in artifact["conditions"]
        if condition["type"] == "argsPostJSONMatch"
    )
    assert json_condition["parameter"] == "env.node_options"
    assert json_condition["value"] == ["*--require*"]
    assert json_condition["valueWildcard"] is True
    assert not {"action", "deny", "alert"}.intersection(artifact)
    assert candidate.candidate_id.endswith(
        candidate.candidate_artifact.content_hash.removeprefix("sha256:")[:16]
    )
    metadata = candidate.candidate_metadata
    assert metadata is not None
    assert metadata.syntax_profile.id == "janus-akamai-like-custom-rule-demo@1"
    assert metadata.syntax_profile.family == "akamai-like-custom-rule"
    assert metadata.syntax_profile.validation_level == "shape-only"
    assert metadata.syntax_profile.deployment_ready is False
    binding = metadata.recommended_policy_binding
    assert binding.action == "deny"
    assert binding.attachment == "security-policy-custom-rule-binding"
    assert binding.embedded_in_artifact is False
    assert binding.requires_operator_review is True


def test_json_body_semantic_judge_uses_target_like_wildcards():
    feature = JsonBodyFieldFeature(
        method="POST",
        content_type="application/json",
        field_path=["env", "node_options"],
        value="--require",
        value_match="contains-token",
    )
    base_conditions = [
        {"type": "requestMethodMatch", "positiveMatch": True, "value": ["POST"]},
        {
            "type": "requestHeaderValueMatch",
            "positiveMatch": True,
            "header": "Content-Type",
            "valueCase": False,
            "valueWildcard": True,
            "value": ["*application/json*"],
        },
    ]
    exact_looking = {
        "operation": "AND",
        "conditions": [
            *base_conditions,
            {
                "type": "argsPostJSONMatch",
                "positiveMatch": True,
                "parameter": "env.node_options",
                "valueCase": True,
                "valueWildcard": True,
                "value": ["--require"],
            },
        ],
    }
    overly_broad = {
        "operation": "AND",
        "conditions": [
            *base_conditions,
            {
                "type": "argsPostJSONMatch",
                "positiveMatch": True,
                "parameter": "env.node_options",
                "valueCase": True,
                "valueWildcard": True,
                "value": ["*"],
            },
        ],
    }

    assert "does not match" in " ".join(
        _akamai_json_body_semantic_errors(json.dumps(exact_looking), feature)
    )
    assert "benign" in " ".join(
        _akamai_json_body_semantic_errors(json.dumps(overly_broad), feature)
    )


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
