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
