"""Wazuh rule -> SentinelOne STAR rule compilation.

The Defense Generation candidate declares `artifact_type`, and `wazuh-rule`
selects this path. What matters is the same property the Akamai compiler is
held to: a rule is either compiled faithfully or not compiled at all, because
the alternative is a detection whose meaning was guessed.
"""

from __future__ import annotations

import json

import pytest

from control_translation.adapters import get_adapter
from control_translation.contracts import ProvenMitigationPattern
from control_translation.translation.wazuh_s1 import (
    compile_sentinelone_star_rule,
    is_wazuh_rule_artifact,
)


def pattern_for(artifact: str, **overrides) -> ProvenMitigationPattern:
    values = {
        "proven_pattern_id": "proven-pattern:candidate:1",
        "vulnerability_id": "CVE-2026-77392",
        "selected_control_class": "edr",
        "discriminator_id": "discriminator:candidate:1",
        "discriminator_description": "Encoded PowerShell spawned from Office",
        "pattern_summary": artifact,
        "proof_record_ids": [
            "mitigation-check-result:1",
            "bypass-validation-result:2",
        ],
        "upstream_artifact_type": "wazuh-rule",
    }
    values.update(overrides)
    return ProvenMitigationPattern(**values)


PROCESS_RULE = """
<group name="sysmon,">
  <rule id="100200" level="12">
    <field name="win.eventdata.image">\\\\powershell\\.exe$</field>
    <field name="win.eventdata.commandLine">-enc</field>
    <description>Encoded PowerShell execution</description>
  </rule>
</group>
"""


def compiled(artifact: str, **overrides) -> dict:
    proposal = compile_sentinelone_star_rule(pattern_for(artifact, **overrides))
    assert proposal is not None, "expected the rule to compile"
    return proposal.candidate_content


def test_artifact_type_selects_this_path():
    assert is_wazuh_rule_artifact("wazuh-rule")
    assert is_wazuh_rule_artifact(" Wazuh-Rule ")
    assert not is_wazuh_rule_artifact("modsecurity")
    assert not is_wazuh_rule_artifact(None)


def test_a_process_rule_compiles_to_a_star_rule():
    data = compiled(PROCESS_RULE)["data"]

    assert data["name"] == "JANUS-CVE-2026-77392-100200"
    assert data["description"] == "Encoded PowerShell execution"
    assert data["queryType"] == "events"
    # S1QL 1.0 stops accepting new rules; 2.0 is the only forward option.
    assert data["queryLang"] == "2.0"
    assert data["s1ql"] == (
        "EventType = 'Process Creation' "
        "AND TgtProcImagePath EndsWithCIS '\\\\powershell.exe' "
        "AND TgtProcCmdLine ContainsCIS '-enc'"
    )


def test_the_compiled_rule_satisfies_the_edr_adapter():
    """The adapter is what the capability validates against, so the compiler
    has to produce something it accepts."""
    adapter = get_adapter("edr-s1")

    result = adapter.validate_syntax(json.dumps(compiled(PROCESS_RULE)))

    assert result.valid, result.errors


def test_the_rule_alerts_rather_than_killing():
    """treatAsThreat drives kill and quarantine. This service has not verified
    the detection on an endpoint, so promoting it is the operator's call."""
    data = compiled(PROCESS_RULE)["data"]

    assert data["treatAsThreat"] == "UNDEFINED"
    assert data["networkQuarantine"] is False


@pytest.mark.parametrize(
    ("level", "severity"),
    [("15", "Critical"), ("12", "Critical"), ("10", "High"), ("7", "Medium"), ("3", "Low")],
)
def test_wazuh_level_maps_to_star_severity(level: str, severity: str):
    artifact = PROCESS_RULE.replace('level="12"', f'level="{level}"')

    assert compiled(artifact)["data"]["severity"] == severity


# ---------------------------------------------------------------------------
# Anchors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("^C:", "TgtProcImagePath StartsWithCIS 'C:'"),
        ("\\\\cmd\\.exe$", "TgtProcImagePath EndsWithCIS '\\\\cmd.exe'"),
        ("^cmd\\.exe$", "TgtProcImagePath = 'cmd.exe'"),
        ("cmd", "TgtProcImagePath ContainsCIS 'cmd'"),
    ],
)
def test_anchors_become_the_matching_s1ql_operator(value: str, expected: str):
    artifact = (
        f'<rule id="1" level="5"><field name="win.eventdata.image">{value}</field>'
        "<description>d</description></rule>"
    )

    assert expected in compiled(artifact)["data"]["s1ql"]


# ---------------------------------------------------------------------------
# Declining
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "power.*shell",   # any run
        "cmd|powershell",  # alternation
        "[Pp]owershell",   # class
        "\\\\w+\\\\.exe",  # character class
        "power.hell",      # a bare dot matches any character
        "(cmd)",           # group
        "cmd?",            # optional
    ],
)
def test_a_pattern_that_is_not_literal_declines(value: str):
    """S1QL has string operators, not regex. Approximating one of these would
    silently widen or narrow the detection, so it is not translated."""
    artifact = (
        f'<rule id="1" level="5"><field name="win.eventdata.image">{value}</field>'
        "<description>d</description></rule>"
    )

    assert compile_sentinelone_star_rule(pattern_for(artifact)) is None


def test_an_unmapped_field_declines_rather_than_being_dropped():
    """Dropping a condition broadens the rule. The field map is the set of
    Wazuh fields with a known S1 counterpart; anything else is not guessed."""
    artifact = (
        '<rule id="1" level="5">'
        '<field name="win.eventdata.image">\\\\cmd\\.exe$</field>'
        '<field name="data.some.vendor.field">value</field>'
        "<description>d</description></rule>"
    )

    assert compile_sentinelone_star_rule(pattern_for(artifact)) is None


def test_a_rule_with_no_fields_declines():
    artifact = '<rule id="1" level="5"><description>d</description></rule>'

    assert compile_sentinelone_star_rule(pattern_for(artifact)) is None


def test_fields_from_two_event_classes_decline():
    """One STAR rule is one event class. Splitting the pattern across two would
    change what the single proven candidate means."""
    artifact = (
        '<rule id="1" level="5">'
        '<field name="win.eventdata.image">\\\\cmd\\.exe$</field>'
        '<field name="win.eventdata.targetFilename">\\\\temp\\\\x</field>'
        "<description>d</description></rule>"
    )

    assert compile_sentinelone_star_rule(pattern_for(artifact)) is None


def test_a_rule_set_declines():
    """The proof loop validated one candidate, not a file of rules."""
    artifact = (
        "<group name='g'>"
        '<rule id="1" level="5"><field name="win.eventdata.image">\\\\a\\.exe$</field>'
        "<description>d</description></rule>"
        '<rule id="2" level="5"><field name="win.eventdata.image">\\\\b\\.exe$</field>'
        "<description>d</description></rule></group>"
    )

    assert compile_sentinelone_star_rule(pattern_for(artifact)) is None


def test_a_non_wazuh_artifact_declines():
    secrule = 'SecRule ARGS:Researcher "@rx attack" "id:1,deny"'

    assert compile_sentinelone_star_rule(pattern_for(secrule)) is None


# ---------------------------------------------------------------------------
# Honesty about what was translated
# ---------------------------------------------------------------------------


def test_a_chained_rule_is_labelled_broader_and_says_why():
    """if_sid inherits the parent rule's conditions. Those conditions are not
    in this artifact, so the query cannot contain them and matches more."""
    artifact = (
        '<rule id="1" level="10"><if_sid>5716</if_sid>'
        '<field name="win.eventdata.image">\\\\cmd\\.exe$</field>'
        "<description>d</description></rule>"
    )

    proposal = compile_sentinelone_star_rule(pattern_for(artifact))

    assert proposal is not None
    assert proposal.translation_label == "broader"
    assert any("if_sid" in limitation for limitation in proposal.limitations)


def test_an_unchained_rule_is_equivalent():
    proposal = compile_sentinelone_star_rule(pattern_for(PROCESS_RULE))

    assert proposal is not None
    assert proposal.translation_label == "equivalent"
    assert not any("if_sid" in limitation for limitation in proposal.limitations)


def test_the_collector_difference_is_stated():
    """Wazuh reads decoded logs; S1QL reads endpoint telemetry. A reader of the
    candidate should not have to know that to understand what they are given."""
    proposal = compile_sentinelone_star_rule(pattern_for(PROCESS_RULE))

    assert any(
        "log events" in limitation and "telemetry" in limitation
        for limitation in proposal.limitations
    )


def test_a_quote_in_a_value_cannot_break_out_of_the_query():
    artifact = (
        '<rule id="1" level="5">'
        "<field name=\"win.eventdata.commandLine\">it's</field>"
        "<description>d</description></rule>"
    )

    s1ql = compiled(artifact)["data"]["s1ql"]

    assert "it\\'s" in s1ql
    # Only the escaped quote is inside the literal; the delimiters still pair.
    delimiters = s1ql.replace("\\'", "")
    assert delimiters.count("'") % 2 == 0
