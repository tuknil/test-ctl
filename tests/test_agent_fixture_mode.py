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
