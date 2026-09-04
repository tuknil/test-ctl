"""Deterministic ModSecurity -> Akamai custom rule execution path."""

from __future__ import annotations

import json
import re

import pytest

from control_translation import capability
from control_translation.adapters.akamai_waf import AkamaiWafAdapter
from control_translation.config import Settings
from control_translation.contracts import (
    ControlTranslationRequest,
    InvokeRequestEnvelope,
    ProofLoopTranslationRequirements,
    ProvenMitigationPattern,
    TargetContext,
)
from control_translation.terminal import TerminalState
from control_translation.translation.modsec_akamai import compile_akamai_custom_rule
from control_translation.upstream import UpstreamRecord

# The orchestration envelope the deployed Temporal caller sends.
CORRELATION_ID = (
    "uat-CVE-2026-77392-checkgen-sanity-20260903T152339Z-"
    "39dec7a7-ba40-4823-8fcf-1557b460a82c"
)
VULNERABILITY_ID = "CVE-2026-77392"
CANDIDATE_ID = "candidate:CVE-2026-77392:waf:299b5006199761b2"
DEFENSE_RESULT_ID = "defense-generation-result:e85fc08fd0be841b04cb101d"
MITIGATION_RESULT_ID = "mitigation-check-result:cc36cf06d9de373492f56335"
BYPASS_RESULT_ID = "bypass-validation-result:bvrun_93b4300a10f78749aa5212e7"

# The proven defense-generation artifact for that candidate.
PROVEN_SECRULE = (
    "SecRule ARGS:Researcher \"@rx (?i)(?:'\\s+OR\\s+'1'='1|"
    "%27\\s*(?:OR|%4f%52)\\s*%271%27%3[dD]%271)\" "
    "\"id:152405,phase:2,deny,status:403,log,"
    "msg:'JANUS candidate: block evidenced Researcher SQLi variants',"
    "tag:'janus-candidate'\""
)


def _pattern(pattern_summary: str, **overrides) -> ProvenMitigationPattern:
    fields = {
        "proven_pattern_id": f"proven-pattern:{CANDIDATE_ID}",
        "vulnerability_id": VULNERABILITY_ID,
        "selected_control_class": "waf",
        "discriminator_id": f"discriminator:{CANDIDATE_ID}",
        "discriminator_description": "Blocks the proven exploitation request.",
        "pattern_summary": pattern_summary,
        "proof_record_ids": [MITIGATION_RESULT_ID, BYPASS_RESULT_ID],
    }
    fields.update(overrides)
    return ProvenMitigationPattern(**fields)


def _compile(pattern_summary: str, **kwargs) -> dict:
    proposal = compile_akamai_custom_rule(_pattern(pattern_summary), **kwargs)
    assert proposal is not None, "compiler declined a rule it should express"
    assert isinstance(proposal.candidate_content, dict)
    # Everything this path emits must survive the adapter's mechanical gate.
    validation = AkamaiWafAdapter().validate_syntax(
        json.dumps(proposal.candidate_content)
    )
    assert validation.valid, validation.errors
    return proposal.candidate_content


def _condition(rule: dict, condition_type: str) -> dict:
    return next(item for item in rule["conditions"] if item["type"] == condition_type)


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------


def test_named_argument_regex_becomes_a_post_argument_condition():
    rule = _compile(PROVEN_SECRULE)

    assert rule["name"] == "JANUS-CVE-2026-77392-Researcher"
    assert rule["description"].startswith("JANUS candidate: block evidenced")
    assert rule["operation"] == "AND"
    condition = _condition(rule, "argsPostMatch")
    assert condition["parameter"] == "Researcher"
    assert condition["positiveMatch"] is True
    assert condition["valueWildcard"] is True
    # (?i) makes the source case-insensitive.
    assert condition["valueCase"] is False
    # Both alternation branches survive, the nested (?:OR|%4f%52) alternation
    # is expanded, and [dD] is enumerated rather than guessed at.
    assert condition["value"] == [
        "*'?*OR?*'1'='1*",
        "*%27*OR*%271%27%3d%271*",
        "*%27*OR*%271%27%3D%271*",
        "*%27*%4f%52*%271%27%3d%271*",
        "*%27*%4f%52*%271%27%3D%271*",
    ]
    assert "janus-candidate" in rule["tag"]


def test_compiled_rule_never_embeds_an_action():
    rule = _compile(PROVEN_SECRULE)

    assert not {"action", "deny", "alert"} & set(rule)


def test_anchored_literal_compiles_to_an_exact_match_with_encodings():
    rule = _compile(
        'SecRule ARGS_POST:token "@rx ^drop table users$" "id:1,deny"'
    )

    condition = _condition(rule, "argsPostMatch")
    assert condition["valueWildcard"] is False
    assert condition["valueCase"] is True
    assert condition["value"] == [
        "drop table users",
        "drop%20table%20users",
        "drop+table+users",
        "drop%2520table%2520users",
    ]


def test_header_rule_maps_to_a_named_header_value_condition():
    rule = _compile(
        'SecRule REQUEST_HEADERS:User-Agent "@rx \\$\\{jndi:" '
        "\"id:2,deny,msg:'Log4Shell JNDI in User-Agent'\""
    )

    condition = _condition(rule, "requestHeaderValueMatch")
    assert condition["header"] == "User-Agent"
    assert condition["value"] == ["*${jndi:*"]


def test_headerless_collection_uses_the_any_header_condition():
    rule = _compile('SecRule REQUEST_HEADERS "@contains ${jndi:" "id:3,deny"')

    condition = _condition(rule, "requestHeaderMatch")
    assert "header" not in condition


def test_negated_operator_flips_positive_match():
    rule = _compile('SecRule REQUEST_METHOD "!@within GET POST" "id:4,deny"')

    condition = _condition(rule, "requestMethodMatch")
    assert condition["positiveMatch"] is False
    assert condition["value"] == ["GET", "POST"]


def test_chained_rules_compile_into_one_and_operation():
    rule = _compile(
        'SecRule REQUEST_URI "@rx ^/api/v1/" "id:5,phase:1,chain,deny"\n'
        'SecRule ARGS:cmd "@contains ;curl " "id:5"'
    )

    assert rule["operation"] == "AND"
    assert [item["type"] for item in rule["conditions"]] == [
        "pathMatch",
        "argsPostMatch",
    ]
    assert _condition(rule, "pathMatch")["value"] == ["/api/v1/*"]


def test_alternative_variables_compile_into_one_or_operation():
    rule = _compile(
        'SecRule ARGS_GET|REQUEST_BODY "@contains ../../etc/passwd" "id:6,deny"'
    )

    assert rule["operation"] == "OR"
    assert [item["type"] for item in rule["conditions"]] == [
        "uriQueryMatch",
        "argsPostMatch",
    ]


def test_lossless_mapping_is_equivalent_and_generalized_mapping_is_narrower():
    exact = compile_akamai_custom_rule(
        _pattern('SecRule ARGS_POST:token "@rx ^drop table users$" "id:1,deny"')
    )
    generalized = compile_akamai_custom_rule(_pattern(PROVEN_SECRULE))

    assert exact is not None and generalized is not None
    assert exact.translation_label == "equivalent"
    assert generalized.translation_label == "narrower"
    assert any(
        "broader set of requests" in item for item in generalized.limitations
    )


def test_args_collection_records_its_query_string_coverage_gap():
    proposal = compile_akamai_custom_rule(
        _pattern('SecRule ARGS "@contains \' OR 1=1" "id:7,deny"')
    )

    assert proposal is not None
    assert any("query-string" in item for item in proposal.limitations)


@pytest.mark.parametrize(
    "pattern_summary",
    [
        # Prose, not a rule.
        "Block requests whose Content-Type header contains OGNL syntax.",
        # No explicit operator: not safely parseable as a match.
        "SecRule ARGS deny SQL injection",
        # Counted repetition has no Akamai wildcard equivalent.
        'SecRule ARGS:u "@rx ^a\\s{2,}b$" "id:8,deny"',
        # Lookarounds cannot be expressed.
        'SecRule ARGS:u "@rx ^a(?=.*b)c$" "id:9,deny"',
        # Quantified multi-character group.
        'SecRule ARGS:u "@rx ^(?:abc)+$" "id:10,deny"',
        # Collection with no documented Akamai condition type.
        'SecRule TX:anomaly_score "@gt 5" "id:11,deny"',
        # Backreferences.
        'SecRule ARGS:u "@rx (a)\\1" "id:12,deny"',
        # Operators whose semantics are not mechanically mappable.
        'SecRule ARGS:u "@validateByteRange 32-126" "id:13,deny"',
        # Regex variable selectors.
        'SecRule ARGS:/^user_/ "@contains x" "id:14,deny"',
    ],
)
def test_unmappable_sources_decline_instead_of_guessing(pattern_summary: str):
    assert compile_akamai_custom_rule(_pattern(pattern_summary)) is None


def test_expansion_is_bounded():
    alternation = "|".join(f"value{index}" for index in range(64))
    assert (
        compile_akamai_custom_rule(
            _pattern(f'SecRule ARGS:u "@rx (?:{alternation})" "id:15,deny"')
        )
        is None
    )


# ---------------------------------------------------------------------------
# Bypass-driven translation requirements
# ---------------------------------------------------------------------------


def _requirements(**overrides) -> ProofLoopTranslationRequirements:
    fields = {
        "original_payload": "Researcher='",
        "bypass_payload": "526573656172636865723d27",
        "bypass_variant_or_encoding": "hexadecimal",
        "constraint_for_next_candidate": "Cover the hexadecimal bypass form.",
        "post_waf_canonical_forms": ["526573656172636865723d27"],
        "effective_request": {"method": "POST", "path": "/public/submit.php"},
        "mutation_location": {"component": "body", "parameter": "Researcher"},
    }
    fields.update(overrides)
    return ProofLoopTranslationRequirements(**fields)


def test_proven_bypass_payloads_are_folded_into_the_matching_condition():
    rule = _compile(
        PROVEN_SECRULE, translation_requirements=_requirements()
    )

    condition = _condition(rule, "argsPostMatch")
    assert "526573656172636865723d27" in condition["value"]
    assert _condition(rule, "pathMatch")["value"] == ["/public/submit.php"]


def test_compiler_declines_when_the_mutated_component_has_no_condition():
    # Bypass Validation mutated a request header, but the proven rule only
    # inspects the body, so the values cannot be OR-ed into it.
    assert (
        compile_akamai_custom_rule(
            _pattern(PROVEN_SECRULE),
            translation_requirements=_requirements(
                mutation_location={"component": "header", "name": "X-Forwarded-For"}
            ),
        )
        is None
    )


# ---------------------------------------------------------------------------
# Engine / capability wiring
# ---------------------------------------------------------------------------


class UnexpectedDoer:
    def propose(self, **kwargs):
        raise AssertionError("the deterministic path must not reach the doer")


def _direct_request(pattern_summary: str, **overrides) -> ControlTranslationRequest:
    return ControlTranslationRequest(
        proven_pattern=_pattern(pattern_summary, **overrides),
        target_context=TargetContext(
            target_technology="akamai-waf",
            target_policy_context_id="akamai-policy:example:rev-17",
        ),
    )


@pytest.mark.parametrize("run_mode", ["fixture", "live"])
def test_proven_rule_is_translated_without_the_doer_in_either_mode(run_mode: str):
    envelope = capability.invoke(
        _direct_request(PROVEN_SECRULE),
        settings=Settings(run_mode=run_mode, model_provider="att"),
        doer=UnexpectedDoer(),
    )

    assert envelope.terminal_state == TerminalState.TRANSLATED
    assert envelope.inference["proposal_source"] == "deterministic-modsec-rule"
    assert envelope.inference["llm_invoked"] is False
    candidate = envelope.structured_result.primary_candidate
    assert candidate is not None
    assert candidate.candidate_artifact.artifact_type == "akamai-waf-rule"
    assert json.loads(candidate.candidate_artifact.content_ref)["conditions"]


def test_compiled_rule_bypasses_the_discriminator_keyword_gate():
    # The adapter's cheap keyword gate does not recognize this prose, but the
    # rule itself compiles, which settles expressibility.
    envelope = capability.invoke(
        _direct_request(
            PROVEN_SECRULE,
            discriminator_description="Opaque producer prose without keywords.",
        ),
        doer=UnexpectedDoer(),
    )

    assert envelope.terminal_state == TerminalState.TRANSLATED
    assert envelope.inference["proposal_source"] == "deterministic-modsec-rule"


def test_unmappable_rule_still_falls_back_to_the_doer():
    envelope = capability.invoke(
        _direct_request('SecRule ARGS:u "@rx ^a\\s{2,}b$" "id:8,deny"')
    )

    assert envelope.terminal_state == TerminalState.TRANSLATED
    assert envelope.inference["proposal_source"] == "translation-doer"


# ---------------------------------------------------------------------------
# Orchestration envelope end to end
# ---------------------------------------------------------------------------


def _upstream_input(capability_name: str, contract_id: str, result_id: str,
                    terminal_state: str, schema: str, table: str) -> dict:
    return {
        "capability": capability_name,
        "contract_id": contract_id,
        "run_id": f"run:{result_id}",
        "result_id": result_id,
        "terminal_state": terminal_state,
        "status": "completed",
        "correlation_id": CORRELATION_ID,
        "result_ref": {
            "system": "databricks",
            "catalog": "36889_janus_dev",
            "schema": schema,
            "table": table,
            "key": result_id,
        },
    }


def _orchestration_body() -> dict:
    return {
        "contract_id": "control-translation@1.0",
        "request_id": "swagger-control-translation-CVE-2026-77392-1",
        "correlation_id": CORRELATION_ID,
        "subject": {
            "vulnerability_id": VULNERABILITY_ID,
            "candidate_id": CANDIDATE_ID,
        },
        "upstream_inputs": [
            _upstream_input(
                "defense-generation", "defense-generation@1.0", DEFENSE_RESULT_ID,
                "candidate-produced", "defense_generation", "defense_generation_results",
            ),
            _upstream_input(
                "mitigation-check", "mitigation-check@1.0", MITIGATION_RESULT_ID,
                "blocked", "mitigation-check", "mitigation_check",
            ),
            _upstream_input(
                "bypass-validation", "capability-completion@1.0", BYPASS_RESULT_ID,
                "no-bypass-found", "bypass_validation", "bypass_validation_results",
            ),
        ],
        "routing_context": {
            "route": "validated",
            "mitigation_check_terminal_state": "blocked",
            "mitigation_check_match": True,
            "bypass_validation_terminal_state": "no-bypass-found",
            "loop_exhausted": False,
            "completed_iterations": 2,
            "max_iterations": 10,
        },
        "provenance": {"caller": "janus-orchestration", "source": "temporal"},
    }


class FakeResolver:
    def __init__(self, records: dict[str, UpstreamRecord]) -> None:
        self.records = records

    def fetch(self, reference, *, cancellation_signal=None):
        return self.records.get(reference.key)


def _orchestration_records() -> dict[str, UpstreamRecord]:
    common = {"vulnerability_id": VULNERABILITY_ID, "candidate_id": CANDIDATE_ID}
    return {
        DEFENSE_RESULT_ID: UpstreamRecord(
            result_id=DEFENSE_RESULT_ID,
            terminal_state="candidate-produced",
            correlation_id=CORRELATION_ID,
            subject_record_revision_id=None,
            request={**common, "selected_control_class": "waf"},
            result={
                **common,
                "primary_candidate": {
                    **common,
                    "selected_control_class": "waf",
                    "discriminator": (
                        "Submit the Researcher parameter with SQL injection "
                        "syntax and observe the authentication bypass."
                    ),
                    "artifact_content": PROVEN_SECRULE,
                },
            },
        ),
        MITIGATION_RESULT_ID: UpstreamRecord(
            result_id=MITIGATION_RESULT_ID,
            terminal_state="blocked",
            correlation_id=CORRELATION_ID,
            subject_record_revision_id=None,
            request={},
            result={**common, "terminal_state": "blocked"},
        ),
        BYPASS_RESULT_ID: UpstreamRecord(
            result_id=BYPASS_RESULT_ID,
            terminal_state="no-bypass-found",
            correlation_id=CORRELATION_ID,
            subject_record_revision_id=None,
            request={},
            result={**common, "terminal_state": "no-bypass-found"},
        ),
    }


def test_orchestration_envelope_compiles_the_referenced_rule_for_akamai():
    result = capability.invoke_envelope(
        InvokeRequestEnvelope.model_validate(_orchestration_body()),
        resolver=FakeResolver(_orchestration_records()),
        settings=Settings(run_mode="fixture", model_provider="none"),
    )

    assert result.terminal_state == TerminalState.TRANSLATED
    assert result.inference["proposal_source"] == "deterministic-modsec-rule"
    assert result.inference["llm_invoked"] is False
    candidate = result.structured_result.primary_candidate
    assert candidate is not None
    assert candidate.target_technology == "akamai-waf"
    assert candidate.candidate_artifact.artifact_type == "akamai-waf-rule"
    rule = json.loads(candidate.candidate_artifact.content_ref)
    assert rule["name"] == "JANUS-CVE-2026-77392-Researcher"
    condition = _condition(rule, "argsPostMatch")
    assert condition["parameter"] == "Researcher"
    assert AkamaiWafAdapter().validate_syntax(
        candidate.candidate_artifact.content_ref
    ).valid
    assert candidate.candidate_metadata is not None
    assert candidate.candidate_metadata.recommended_policy_binding.action == "deny"


# ---------------------------------------------------------------------------
# Encoding ladders
# ---------------------------------------------------------------------------

# Defense generation enumerates recursive encodings of one character per group.
# Expanding these positionally is a cross-product: 7**5 = 16807 values, far past
# the value cap. The compiler aligns the ladders and emits one value per depth.
ENCODING_LADDER_RULE = (
    'SecRule REQUEST_BODY "@rx person'
    r"(?:\[|%5B|%255B|%25255B|%2525255B|%252525255B|%25252525255B)0"
    r"(?:\]|%5D|%255D|%25255D|%2525255D|%252525255D|%25252525255D)"
    r"(?:\[|%5B|%255B|%25255B|%2525255B|%252525255B|%25252525255B)"
    r"(?:\]|%5D|%255D|%25255D|%2525255D|%252525255D|%25252525255D)"
    "(?:=|%3D|%253D|%25253D|%2525253D|%252525253D|%25252525253D)malicious\" "
    "\"id:108001,phase:2,deny,status:403,log,msg:'JANUS candidate',"
    "tag:'janus-candidate'\""
)


def test_encoding_ladders_align_by_depth_instead_of_exploding():
    rule = _compile(ENCODING_LADDER_RULE)

    assert _condition(rule, "argsPostMatch")["value"] == [
        "*person[0][]=malicious*",
        "*person%5B0%5D%5B%5D%3Dmalicious*",
        "*person%255B0%255D%255B%255D%253Dmalicious*",
        "*person%25255B0%25255D%25255B%25255D%25253Dmalicious*",
        "*person%2525255B0%2525255D%2525255B%2525255D%2525253Dmalicious*",
        "*person%252525255B0%252525255D%252525255B%252525255D%252525253Dmalicious*",
        "*person%25252525255B0%25252525255D%25252525255B%25252525255D"
        "%25252525253Dmalicious*",
    ]


def test_aligned_ladder_values_are_a_subset_of_the_source_rule():
    """Every emitted value is one the source matches, so it cannot over-block."""
    source = re.compile(
        r"person(?:\[|%5B|%255B|%25255B|%2525255B|%252525255B|%25252525255B)0"
        r"(?:\]|%5D|%255D|%25255D|%2525255D|%252525255D|%25252525255D)"
        r"(?:\[|%5B|%255B|%25255B|%2525255B|%252525255B|%25252525255B)"
        r"(?:\]|%5D|%255D|%25255D|%2525255D|%252525255D|%25252525255D)"
        r"(?:=|%3D|%253D|%25253D|%2525253D|%252525253D|%25252525253D)malicious"
    )
    rule = _compile(ENCODING_LADDER_RULE)

    for value in _condition(rule, "argsPostMatch")["value"]:
        assert source.search(value.strip("*")), f"{value} is not matched by the source"


def test_aligned_ladder_is_labelled_narrower_and_says_why():
    proposal = compile_akamai_custom_rule(_pattern(ENCODING_LADDER_RULE))

    assert proposal is not None
    assert proposal.translation_label == "narrower"
    assert any("differing depths" in item for item in proposal.limitations)
    # Aligning ladders drops combinations; it never adds any.
    assert not any("broader set of requests" in item for item in proposal.limitations)


def test_ordinary_alternation_is_not_treated_as_a_ladder():
    rule = _compile('SecRule ARGS:u "@rx (?:alpha|beta|gamma)" "id:1,deny"')

    assert len(_condition(rule, "argsPostMatch")["value"]) == 3


def test_ladders_of_differing_depths_decline():
    # There is no common depth to align on, so the compiler refuses to guess
    # which depths pair up.
    assert (
        compile_akamai_custom_rule(
            _pattern(r'SecRule REQUEST_BODY "@rx a(?:\[|%5B|%255B)b(?:\]|%5D)c" "id:1,deny"')
        )
        is None
    )


def test_aligned_expansion_is_still_bounded():
    groups = r"(?:\[|%5B|%255B|%25255B|%2525255B|%252525255B|%25252525255B)" * 3
    alternation = "(?:" + "|".join("abc"[index % 3] * (index + 1) for index in range(10)) + ")"
    rule = f'SecRule REQUEST_BODY "@rx {alternation}{groups}" "id:1,deny"'

    # 10 branches x 7 depths = 70 values, past the 32-value cap.
    assert compile_akamai_custom_rule(_pattern(rule)) is None
