import json

from control_translation.agents.translation_agent import (
    FixtureTranslationDoer,
    TranslationProposal,
    build_translation_doer,
)
from control_translation.config import Settings
from control_translation.providers.fixtures import get_fixture_pattern


def test_fixture_doer_returns_typed_proposal_for_akamai():
    doer = FixtureTranslationDoer()
    pattern = get_fixture_pattern("proven-pattern:CVE-EXAMPLE:waf:3")
    assert pattern is not None

    proposal = doer.propose(
        pattern=pattern,
        target_technology="akamai-waf",
        artifact_type="akamai-waf-rule",
        snapshot=None,
    )
    assert isinstance(proposal, TranslationProposal)
    assert proposal.translation_label in ("exact", "equivalent", "narrower")
    assert proposal.candidate_content
    assert proposal.answer_kind == "construction"


def test_fixture_doer_returns_typed_proposal_for_firewall():
    doer = FixtureTranslationDoer()
    pattern = get_fixture_pattern("proven-pattern:CVE-EXAMPLE:firewall:1")
    assert pattern is not None

    proposal = doer.propose(
        pattern=pattern,
        target_technology="firewall-generic",
        artifact_type="firewall-rule",
        snapshot=None,
    )
    assert proposal.candidate_content
    assert "deny" in proposal.candidate_content.lower()


def test_build_translation_doer_returns_fixture_doer_in_fixture_mode():
    settings = Settings(run_mode="fixture")
    doer = build_translation_doer(settings)
    assert isinstance(doer, FixtureTranslationDoer)


def test_build_translation_doer_returns_live_doer_in_live_mode():
    from control_translation.agents.translation_agent import LiveTranslationDoer

    settings = Settings(run_mode="live", model_provider="openai", model_name="gpt-4o-mini")
    doer = build_translation_doer(settings)
    assert isinstance(doer, LiveTranslationDoer)
    # Do not call .propose() here: that would require a real API key and
    # network access. This test only verifies construction/wiring.


def test_att_inference_settings_require_endpoint_and_key():
    settings = Settings(
        run_mode="live",
        model_provider="att-inference",
        model_name="att-approved-model",
        att_inference_base_url="https://inference.example.att.com/v1",
        att_inference_api_key="test-key",
    )

    assert settings.is_att_inference is True
    assert settings.credentials_configured is True


def test_att_inference_settings_report_missing_credentials():
    settings = Settings(run_mode="live", model_provider="att-inference")
    assert settings.credentials_configured is False
    assert settings.ready is False
    assert settings.configuration_errors


def test_fixture_settings_need_no_model_configuration():
    settings = Settings()
    assert settings.run_mode == "fixture"
    assert settings.ready is True


def test_invalid_runtime_settings_are_not_ready():
    settings = Settings(run_mode="unexpected", model_request_timeout_seconds=0)
    assert settings.ready is False
    assert "RUN_MODE must be either 'fixture' or 'live'." in settings.configuration_errors


def test_build_translation_doer_returns_att_adapter_for_live_att_inference():
    from control_translation.agents.translation_agent import AttInferenceTranslationDoer

    settings = Settings(
        run_mode="live",
        model_provider="att-inference",
        model_name="att-cso-gpt-4.1-mini",
        att_inference_base_url="https://inference.example.att.com/v1",
        att_inference_api_key="test-key",
    )

    assert isinstance(build_translation_doer(settings), AttInferenceTranslationDoer)


def test_translation_proposal_accepts_structured_and_text_candidates() -> None:
    base = {
        "translation_label": "equivalent",
        "justification": "test",
    }
    assert isinstance(
        TranslationProposal(candidate_content={"operation": "AND"}, **base).candidate_content,
        dict,
    )
    assert isinstance(
        TranslationProposal(candidate_content=[{"type": "condition"}], **base).candidate_content,
        list,
    )
    assert TranslationProposal(candidate_content="set rule action deny", **base).candidate_content == "set rule action deny"


def test_att_inference_preserves_structured_regex_candidate(monkeypatch) -> None:
    from control_translation.agents import translation_agent
    from control_translation.agents.translation_agent import AttInferenceTranslationDoer

    regex = r"(?i)(?:'\s+OR\s+'1'='1|%27\s*OR\s*%271%27%3[dD]%271)"
    candidate = {
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
    outer = {
        "candidate_content": candidate,
        "translation_label": "equivalent",
        "justification": "translated",
        "translation_assumptions": [],
        "limitations": [],
        "answer_kind": "construction",
    }
    response_body = {
        "choices": [{"message": {"content": json.dumps(outer)}}]
    }
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(response_body).encode("utf-8")

    def fake_urlopen(request, timeout):
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr(translation_agent, "urlopen", fake_urlopen)
    settings = Settings(
        run_mode="live",
        model_provider="att-inference",
        model_name="att-approved-model",
        att_inference_base_url="https://inference.example.att.com/v1",
        att_inference_api_key="test-key",
    )
    pattern = get_fixture_pattern("proven-pattern:CVE-EXAMPLE:waf:3")
    assert pattern is not None

    proposal = AttInferenceTranslationDoer(settings).propose(
        pattern=pattern,
        target_technology="akamai-waf",
        artifact_type="akamai-waf-rule",
        snapshot=None,
    )

    assert isinstance(proposal.candidate_content, dict)
    assert proposal.candidate_content["conditions"][0]["value"] == [regex]
    system_prompt = captured["payload"]["messages"][0]["content"]
    assert "JSON object, not a JSON-encoded string" in system_prompt
