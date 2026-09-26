"""Wazuh rule -> SentinelOne STAR rule compilation.

Defense Generation declares `artifact_type`, and `wazuh-rule` selects this
path. The artifact it emits uses its own canonical observable vocabulary with
`type="pcre2"`, so the first test here is the producer's own artifact, verbatim
-- a hand-authored Sysmon-style rule would prove nothing about the MVP path.

The rest is the fail-closed property. A Wazuh rule ANDs its conditions, so a
condition this cannot express exactly makes the whole rule undecidable: drop
one and the detection broadens, invert one and it reverses. Every case below
that declines is a case where a partial translation would have been wrong.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from control_translation.adapters import get_adapter
from control_translation.contracts import ProvenMitigationPattern
from control_translation.translation.wazuh_s1 import (
    compile_sentinelone_star_rule,
    decline_reason,
    is_wazuh_rule_artifact,
)

FIXTURE = Path(__file__).parent / "fixtures" / "defense-generation" / "wazuh-candidate.xml"

# The exact Defense Generation artifact. Read from the fixture rather than
# inlined so it stays the producer's bytes.
PRODUCER_ARTIFACT = FIXTURE.read_text()


def pattern_for(artifact: str, **overrides) -> ProvenMitigationPattern:
    values = {
        "proven_pattern_id": "proven-pattern:candidate:1",
        "vulnerability_id": "CVE-2026-77392",
        "selected_control_class": "edr",
        "discriminator_id": "discriminator:candidate:1",
        "discriminator_description": "Encoded PowerShell execution",
        "pattern_summary": artifact,
        "proof_record_ids": [
            "mitigation-check-result:1",
            "bypass-validation-result:2",
        ],
        "upstream_artifact_type": "wazuh-rule",
    }
    values.update(overrides)
    return ProvenMitigationPattern(**values)


def rule(*fields: str, attributes: str = 'id="1" level="10"', extra: str = "") -> str:
    return (
        f"<rule {attributes}>"
        + "".join(fields)
        + extra
        + "<description>d</description></rule>"
    )


def field(name: str, value: str, *, engine: str = "pcre2", negate: str = "") -> str:
    negation = f' negate="{negate}"' if negate else ""
    engine_attribute = f' type="{engine}"' if engine else ""
    return f'<field name="{name}"{engine_attribute}{negation}>{value}</field>'


PROCESS_EVENT = field("event.type", "^Process Creation$")


def compiled(artifact: str, **overrides) -> dict:
    proposal = compile_sentinelone_star_rule(pattern_for(artifact, **overrides))
    assert proposal is not None, f"expected a candidate: {decline_reason(pattern_for(artifact))}"
    return proposal.candidate_content


def declined(artifact: str) -> str:
    """Assert the rule declines and return why."""
    assert compile_sentinelone_star_rule(pattern_for(artifact)) is None
    reason = decline_reason(pattern_for(artifact))
    assert reason, "a decline must say why"
    return reason


# ---------------------------------------------------------------------------
# The producer's artifact
# ---------------------------------------------------------------------------


def test_artifact_type_selects_this_path():
    assert is_wazuh_rule_artifact("wazuh-rule")
    assert is_wazuh_rule_artifact(" Wazuh-Rule ")
    assert not is_wazuh_rule_artifact("modsecurity")
    assert not is_wazuh_rule_artifact(None)


def test_the_defense_generation_artifact_compiles():
    """The MVP path. This artifact is what the producer emits and what the
    mitigation-check service proves against."""
    data = compiled(PRODUCER_ARTIFACT)["data"]

    assert data["s1ql"] == (
        "EventType = 'Process Creation' "
        "AND SrcProcCmdLine ContainsCIS '-EncodedCommand'"
    )
    assert data["name"] == "JANUS-CVE-2026-77392-103047"
    assert data["description"] == "EDR proof"
    assert data["severity"] == "Critical"
    assert data["queryLang"] == "2.0"


def test_the_compiled_producer_artifact_satisfies_the_edr_adapter():
    adapter = get_adapter("edr-s1")

    result = adapter.validate_syntax(json.dumps(compiled(PRODUCER_ARTIFACT)))

    assert result.valid, result.errors


def test_the_fixture_is_the_producers_dialect_not_a_sysmon_rule():
    """Guards the fixture itself. If it drifts to win.eventdata.* naming it
    stops testing the producer path, which is how this went wrong before."""
    assert 'type="pcre2"' in PRODUCER_ARTIFACT
    assert 'name="event.type"' in PRODUCER_ARTIFACT
    assert "src.process.cmdline" in PRODUCER_ARTIFACT
    assert "win.eventdata" not in PRODUCER_ARTIFACT


def test_the_rule_alerts_rather_than_killing():
    data = compiled(PRODUCER_ARTIFACT)["data"]

    assert data["treatAsThreat"] == "UNDEFINED"
    assert data["networkQuarantine"] is False


# ---------------------------------------------------------------------------
# The observable vocabulary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("event_type", "observable", "value", "expected"),
    [
        (
            "Process Creation", "src.process.name", "(?i)powershell\\.exe",
            "SrcProcName ContainsCIS 'powershell.exe'",
        ),
        (
            "Process Creation", "src.process.cmdline", "(?i)-enc",
            "SrcProcCmdLine ContainsCIS '-enc'",
        ),
        (
            "File Creation", "tgt.file.path", "(?i)\\\\Temp\\\\payload",
            "TgtFilePath ContainsCIS '\\\\Temp\\\\payload'",
        ),
        (
            "Registry Key Create", "registry.keyPath", "(?i)CurrentVersion",
            "RegistryKeyPath ContainsCIS 'CurrentVersion'",
        ),
    ],
)
def test_each_producer_observable_maps_to_its_s1_field(
    event_type: str, observable: str, value: str, expected: str
):
    artifact = rule(field("event.type", f"^{event_type}$"), field(observable, value))

    assert expected in compiled(artifact)["data"]["s1ql"]


def test_src_process_is_the_executed_process_not_its_parent():
    """The producer's telemetry puts the executed command line in
    src.process.cmdline, and the documented S1QL example matches the same thing
    with SrcProcCmdLine. Mapping it to TgtProcCmdLine would build a rule about
    the parent process."""
    s1ql = compiled(PRODUCER_ARTIFACT)["data"]["s1ql"]

    assert "SrcProcCmdLine" in s1ql
    assert "TgtProc" not in s1ql


@pytest.mark.parametrize(
    ("event_type", "severity"),
    [("Process Creation", "process"), ("File Creation", "file")],
)
def test_recognized_event_classes_become_the_event_type(event_type: str, severity: str):
    observable = (
        field("src.process.cmdline", "(?i)x")
        if severity == "process"
        else field("tgt.file.path", "(?i)x")
    )
    artifact = rule(field("event.type", f"^{event_type}$"), observable)

    assert compiled(artifact)["data"]["s1ql"].startswith(f"EventType = '{event_type}'")


# ---------------------------------------------------------------------------
# Fail closed: field attributes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("negate", ["yes", "YES", "true", "1"])
def test_a_negated_field_declines_rather_than_being_reversed(negate: str):
    """Emitted positively, a negated condition matches exactly what the rule
    excludes. This is the case where a partial translation is worst."""
    artifact = rule(
        PROCESS_EVENT,
        field("src.process.cmdline", "(?i)-enc", negate=negate),
    )

    assert "negated" in declined(artifact)


def test_a_negated_event_type_declines():
    artifact = rule(
        field("event.type", "^Process Creation$", negate="yes"),
        field("src.process.cmdline", "(?i)-enc"),
    )

    assert "negated" in declined(artifact)


def test_the_osmatch_engine_declines_because_anchors_are_literal_there():
    """In osmatch, "^" and "$" are ordinary characters. Treating them as
    anchors would change what the rule matches."""
    artifact = rule(
        PROCESS_EVENT, field("src.process.cmdline", "^-enc$", engine="osmatch")
    )

    assert "osmatch" in declined(artifact)


def test_a_field_with_no_name_declines():
    artifact = rule(PROCESS_EVENT, '<field type="pcre2">value</field>')

    assert "no name" in declined(artifact)


def test_an_empty_pattern_declines():
    artifact = rule(PROCESS_EVENT, field("src.process.cmdline", ""))

    assert "no pattern" in declined(artifact)


# ---------------------------------------------------------------------------
# Fail closed: conditions outside the <field> vocabulary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "condition",
    [
        "<match>suspicious</match>",
        "<regex>susp.*</regex>",
        "<pcre2>susp.*</pcre2>",
        "<srcip>10.0.0.1</srcip>",
        "<dstport>445</dstport>",
        "<user>admin</user>",
        "<program_name>sshd</program_name>",
        "<decoded_as>auditd</decoded_as>",
        "<if_sid>5716</if_sid>",
        "<if_group>sysmon_event1</if_group>",
        "<same_source_ip />",
        "<status>failed</status>",
        "<url>/admin</url>",
    ],
)
def test_a_condition_outside_the_field_vocabulary_declines(condition: str):
    """Every one of these narrows the Wazuh rule. Ignoring it makes the STAR
    query match more than the rule does."""
    artifact = rule(
        PROCESS_EVENT, field("src.process.cmdline", "(?i)-enc"), extra=condition
    )

    reason = declined(artifact)
    assert "broaden" in reason or "cannot express" in reason or "unrecognized" in reason


@pytest.mark.parametrize("attribute", ["frequency", "timeframe"])
def test_a_correlation_rule_declines(attribute: str):
    """One STAR query matches one event; a threshold over several is not
    expressible."""
    artifact = rule(
        PROCESS_EVENT,
        field("src.process.cmdline", "(?i)-enc"),
        attributes=f'id="1" level="10" {attribute}="8"',
    )

    assert attribute in declined(artifact)


def test_an_unrecognized_element_declines():
    artifact = rule(
        PROCESS_EVENT,
        field("src.process.cmdline", "(?i)-enc"),
        extra="<some_future_condition>x</some_future_condition>",
    )

    assert "unrecognized" in declined(artifact)


def test_metadata_elements_do_not_block_compilation():
    artifact = rule(
        PROCESS_EVENT,
        field("src.process.cmdline", "(?i)-enc"),
        extra="<group>janus,</group><options>no_full_log</options><mitre>T1059</mitre>",
    )

    assert compile_sentinelone_star_rule(pattern_for(artifact)) is not None


# ---------------------------------------------------------------------------
# Fail closed: observables and event classes
# ---------------------------------------------------------------------------


def test_an_observable_with_no_s1_counterpart_declines_by_name():
    """script.content is in the producer's vocabulary but has no Deep
    Visibility counterpart this can name. The decline says which observable
    stopped it rather than reporting an unknown field."""
    artifact = rule(PROCESS_EVENT, field("script.content", "(?i)Invoke-Expression"))

    reason = declined(artifact)
    assert "script.content" in reason
    assert "script-content observable" in reason


def test_an_unknown_observable_declines():
    artifact = rule(PROCESS_EVENT, field("some.vendor.field", "(?i)x"))

    assert "vocabulary" in declined(artifact)


def test_an_unrecognized_event_class_declines():
    """Passing an unknown value through would build a rule that is valid and
    never fires, which a detection cannot report."""
    artifact = rule(
        field("event.type", "^Sysmon Event 42$"),
        field("src.process.cmdline", "(?i)-enc"),
    )

    assert "never match" in declined(artifact)


def test_an_observable_not_present_on_the_event_class_declines():
    """A file path is not on a process-creation event, so the conjunction could
    never be satisfied."""
    artifact = rule(PROCESS_EVENT, field("tgt.file.path", "(?i)payload"))

    assert "not observable" in declined(artifact)


def test_a_rule_without_an_event_type_declines():
    artifact = rule(field("src.process.cmdline", "(?i)-enc"))

    assert "event class" in declined(artifact)


def test_a_rule_constraining_only_the_event_type_declines():
    """It would alert on every process creation on every endpoint."""
    artifact = rule(PROCESS_EVENT)

    assert "every event" in declined(artifact)


def test_an_unanchored_event_type_declines():
    artifact = rule(
        field("event.type", "(?i)Process"), field("src.process.cmdline", "(?i)-enc")
    )

    assert "anchored" in declined(artifact)


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("(?i)-enc", "SrcProcCmdLine ContainsCIS '-enc'"),
        ("-enc", "SrcProcCmdLine Contains '-enc'"),
        ("(?i)^powershell", "SrcProcCmdLine StartsWithCIS 'powershell'"),
        ("^powershell", "SrcProcCmdLine StartsWith 'powershell'"),
        ("(?i)\\.ps1$", "SrcProcCmdLine EndsWithCIS '.ps1'"),
        ("^exact\\.value$", "SrcProcCmdLine = 'exact.value'"),
    ],
)
def test_anchors_and_the_case_flag_choose_the_operator(value: str, expected: str):
    """(?i) is the one inline flag with an exact counterpart: the CIS operators
    are case-insensitive, and their plain forms are not. Using CIS for a
    case-sensitive pattern would broaden every match."""
    artifact = rule(PROCESS_EVENT, field("src.process.cmdline", value))

    assert expected in compiled(artifact)["data"]["s1ql"]


def test_a_case_insensitive_exact_match_declines():
    """There is no case-insensitive equality operator here to vouch for, and
    widening it to a substring match would change the rule."""
    artifact = rule(PROCESS_EVENT, field("src.process.cmdline", "(?i)^exact$"))

    assert "case-insensitive exact" in declined(artifact)


@pytest.mark.parametrize(
    "value",
    [
        "power.*shell",
        "cmd|powershell",
        "[Pp]owershell",
        "\\w+\\.exe",
        "power.hell",
        "(cmd)",
        "cmd?",
        "(?s)cmd",
    ],
)
def test_a_pattern_that_is_not_literal_declines(value: str):
    """S1QL compares strings. Approximating a regex would silently widen or
    narrow the detection."""
    artifact = rule(PROCESS_EVENT, field("src.process.cmdline", value))

    assert compile_sentinelone_star_rule(pattern_for(artifact)) is None


def test_an_escaped_dollar_is_a_literal_not_an_anchor():
    artifact = rule(PROCESS_EVENT, field("src.process.cmdline", "(?i)cost\\$"))

    assert "ContainsCIS 'cost$'" in compiled(artifact)["data"]["s1ql"]


def test_a_quote_in_a_value_cannot_break_out_of_the_query():
    artifact = rule(PROCESS_EVENT, field("src.process.cmdline", "(?i)it's"))

    s1ql = compiled(artifact)["data"]["s1ql"]

    assert "it\\'s" in s1ql
    delimiters = s1ql.replace("\\'", "")
    assert delimiters.count("'") % 2 == 0


# ---------------------------------------------------------------------------
# Artifact shape
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("level", "severity"),
    [("15", "Critical"), ("12", "Critical"), ("10", "High"), ("7", "Medium"), ("3", "Low")],
)
def test_wazuh_level_maps_to_star_severity(level: str, severity: str):
    artifact = rule(
        PROCESS_EVENT,
        field("src.process.cmdline", "(?i)-enc"),
        attributes=f'id="1" level="{level}"',
    )

    assert compiled(artifact)["data"]["severity"] == severity


def test_a_rule_set_declines():
    artifact = (
        "<group name='g'>"
        + rule(PROCESS_EVENT, field("src.process.cmdline", "(?i)a"))
        + rule(PROCESS_EVENT, field("src.process.cmdline", "(?i)b"))
        + "</group>"
    )

    assert "one proven candidate" in declined(artifact)


def test_a_non_wazuh_artifact_declines():
    secrule = 'SecRule ARGS:Researcher "@rx attack" "id:1,deny"'

    assert compile_sentinelone_star_rule(pattern_for(secrule)) is None


def test_malformed_xml_declines_with_a_reason():
    assert "well-formed" in declined("<rule id='1'><field name='event.type'>")


def test_the_collector_difference_is_stated():
    """Wazuh reads decoded logs; S1QL reads endpoint telemetry. A reader of the
    candidate should not have to know that to understand what they are given."""
    proposal = compile_sentinelone_star_rule(pattern_for(PRODUCER_ARTIFACT))

    assert any(
        "log events" in limitation and "telemetry" in limitation
        for limitation in proposal.limitations
    )


def test_every_emitted_candidate_is_equivalent():
    """Nothing partial is emitted, so there is no broader or narrower case."""
    proposal = compile_sentinelone_star_rule(pattern_for(PRODUCER_ARTIFACT))

    assert proposal.translation_label == "equivalent"
