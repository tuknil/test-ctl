"""Deterministic Wazuh rule -> SentinelOne STAR rule compilation.

The Defense Generation candidate names what it produced in `artifact_type`.
When that is `wazuh-rule`, the authoritative artifact is a Wazuh XML rule and
the target is SentinelOne, so the candidate is compiled here in code rather
than proposed by a model -- the same posture the ModSecurity -> Akamai path
takes, and for the same reason: the upstream artifact is executable and
authoritative, so guessing at it is worse than declining.

What this does not do is pretend the two products see the same thing. A Wazuh
rule matches decoded *log events*; an S1QL query matches *endpoint telemetry*.
The mapping below is only the fields where a Sysmon or auditd log field has a
direct S1 telemetry counterpart. Anything outside that map declines, so a rule
is never emitted from a field whose meaning was guessed.

The STAR shape is the `POST /web/api/v2.1/cloud-detection/rules` body described
in `docs/syntexresearch.md`; it has not been validated against a live console.
"""

from __future__ import annotations

import xml.etree.ElementTree as ElementTree

from control_translation.agents.translation_agent import TranslationProposal
from control_translation.contracts import ProvenMitigationPattern

# The artifact_type a Defense Generation candidate uses for a Wazuh rule.
WAZUH_ARTIFACT_TYPE = "wazuh-rule"

# Wazuh log fields that have a direct SentinelOne telemetry counterpart, with
# the S1 event class each one implies. A field outside this map is not
# translated and not guessed at.
_FIELD_MAP: dict[str, tuple[str, str]] = {
    # Sysmon event 1 / auditd execve: process execution.
    "win.eventdata.image": ("TgtProcImagePath", "Process Creation"),
    "win.eventdata.originalfilename": ("TgtProcName", "Process Creation"),
    "win.eventdata.commandline": ("TgtProcCmdLine", "Process Creation"),
    "win.eventdata.parentimage": ("SrcProcImagePath", "Process Creation"),
    "win.eventdata.parentcommandline": ("SrcProcCmdLine", "Process Creation"),
    "win.eventdata.user": ("TgtProcUser", "Process Creation"),
    "audit.exe": ("TgtProcImagePath", "Process Creation"),
    "audit.execve.a0": ("TgtProcCmdLine", "Process Creation"),
    # Sysmon event 11: file creation.
    "win.eventdata.targetfilename": ("TgtFilePath", "File Creation"),
    # Sysmon event 3: network connection.
    "win.eventdata.destinationip": ("DstIP", "IP Connect"),
    "win.eventdata.destinationport": ("DstPort", "IP Connect"),
    "win.eventdata.destinationhostname": ("DstHost", "IP Connect"),
}

# Regex constructs this cannot translate into an S1QL operator. A value
# carrying one of these declines rather than being matched approximately. A
# bare "." is in here on purpose: in a Wazuh pattern it matches any character,
# so treating it as a literal dot would narrow the rule silently. A literal dot
# is written "\." and is unescaped below.
_UNTRANSLATABLE = frozenset("*+?[]{}()|.")

# Backslash escapes that denote a literal character, so unescaping them loses
# nothing. Anything else after a backslash ("\d", "\w", "\s") is a character
# class and has no S1QL equivalent.
_LITERAL_ESCAPES = frozenset(".\\-/@:^$ ")

# Fields compared as numbers rather than strings.
_NUMERIC_FIELDS = frozenset({"DstPort"})

# Wazuh level (0-15) to the four STAR severities.
_SEVERITY_BANDS = ((12, "Critical"), (9, "High"), (6, "Medium"), (0, "Low"))


class _Condition:
    """One S1QL comparison derived from one Wazuh field."""

    def __init__(self, s1ql_field: str, operator: str, value: str) -> None:
        self.s1ql_field = s1ql_field
        self.operator = operator
        self.value = value

    def render(self) -> str:
        if self.operator == "numeric-equals":
            return f"{self.s1ql_field} = {self.value}"
        escaped = self.value.replace("\\", "\\\\").replace("'", "\\'")
        return f"{self.s1ql_field} {self.operator} '{escaped}'"


def compile_sentinelone_star_rule(
    pattern: ProvenMitigationPattern,
) -> TranslationProposal | None:
    """Compile the proven Wazuh rule into a STAR rule, or return None.

    None means the rule uses something this cannot express faithfully; the
    caller then declines rather than falling back to a guess.
    """
    rule = _parse_rule(pattern.pattern_summary)
    if rule is None:
        return None

    conditions: list[_Condition] = []
    event_types: set[str] = set()
    for element in rule.findall("field"):
        name = (element.get("name") or "").strip().lower()
        mapped = _FIELD_MAP.get(name)
        if mapped is None:
            # An unmapped field carries part of the rule's meaning. Emitting
            # without it would silently broaden the detection.
            return None
        condition = _condition_for(mapped[0], element.text or "")
        if condition is None:
            return None
        conditions.append(condition)
        event_types.add(mapped[1])

    if not conditions:
        return None
    if len(event_types) > 1:
        # One STAR rule is one event class; splitting would change what the
        # single proven pattern means.
        return None

    event_type = next(iter(event_types))
    level = _rule_level(rule)
    description = _text_of(rule, "description") or pattern.discriminator_description

    # A rule chained to a parent (if_sid / if_group) inherits that parent's
    # conditions, which are not in this file and so are not in the query.
    inherited = [
        element.tag
        for element in rule
        if element.tag in ("if_sid", "if_group", "if_matched_sid")
    ]

    clauses = [f"EventType = '{event_type}'"] + [c.render() for c in conditions]
    star_rule = {
        "data": {
            "name": _rule_name(pattern, rule),
            "description": description,
            "severity": _severity_for(level),
            "queryType": "events",
            "queryLang": "2.0",
            "s1ql": " AND ".join(clauses),
            "expirationMode": "Permanent",
            "networkQuarantine": False,
            # Alert-only. Promoting to Malicious or Suspicious turns on kill
            # and quarantine, which is an operator decision at binding time --
            # the same reason the Akamai path leaves the action to the policy.
            "treatAsThreat": "UNDEFINED",
        }
    }

    assumptions = [
        "The Wazuh rule in the upstream defense-generation artifact is the "
        "authoritative source of the match semantics.",
        "The Wazuh log fields used by the rule are sourced from Sysmon or "
        "auditd telemetry that SentinelOne observes independently on the same "
        "endpoint.",
        "The STAR rule is scoped at creation time; no account, site or group "
        "filter is asserted here.",
        "Backslashes in a path are doubled inside the S1QL string literal. "
        "The console is not reachable from here, so that escaping convention "
        "is taken from the query examples rather than confirmed.",
    ]
    limitations = [
        "The candidate is shape-validated only and has not been created in a "
        "SentinelOne console.",
        "Wazuh matches decoded log events and S1QL matches endpoint telemetry; "
        "the two observe the same activity through different collectors, so "
        "timing and field coverage are not identical.",
        "treatAsThreat is UNDEFINED, so the rule alerts without killing or "
        "quarantining. Promoting it is an operator decision.",
    ]

    label = "equivalent"
    if inherited:
        label = "broader"
        limitations.append(
            "The Wazuh rule is chained to a parent rule via "
            f"{', '.join(sorted(set(inherited)))}; the parent's conditions are "
            "not present in this artifact and are therefore not in the query, "
            "so the STAR rule matches more than the Wazuh rule does."
        )

    return TranslationProposal(
        candidate_content=star_rule,
        translation_label=label,
        justification=(
            "Compiled the proven Wazuh rule deterministically into a "
            f"SentinelOne STAR rule: {', '.join(sorted(_FIELD_MAP[name][0] for name in _used_fields(rule)))} "
            f"-> S1QL over {event_type} events."
        ),
        translation_assumptions=assumptions,
        limitations=limitations,
    )


def _used_fields(rule: ElementTree.Element) -> list[str]:
    return [
        (element.get("name") or "").strip().lower()
        for element in rule.findall("field")
        if (element.get("name") or "").strip().lower() in _FIELD_MAP
    ]


def _parse_rule(artifact: str) -> ElementTree.Element | None:
    """Return the single <rule> element, or None when there is not exactly one."""
    text = artifact.strip()
    if not text:
        return None
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return None

    if root.tag == "rule":
        return root
    rules = root.findall(".//rule")
    # More than one rule is more than one proven pattern; this compiles the
    # single candidate the proof loop validated, not a rule set.
    return rules[0] if len(rules) == 1 else None


def _condition_for(s1ql_field: str, raw_value: str) -> _Condition | None:
    """Translate one Wazuh field value into an S1QL comparison.

    Wazuh field values are patterns. Only the anchors are translated, because
    they map exactly onto S1QL operators; any other regex construct declines.
    """
    value = raw_value.strip()
    if not value:
        return None

    starts = value.startswith("^")
    body = value[1:] if starts else value
    # A trailing "$" anchors, unless it is itself escaped as a literal.
    ends = body.endswith("$") and not body.endswith("\\$")
    body = body[:-1] if ends else body

    core = _unescape(body)
    if not core:
        return None

    numeric = core.isdigit() and s1ql_field in _NUMERIC_FIELDS
    if starts and ends:
        return _Condition(s1ql_field, "numeric-equals" if numeric else "=", core)
    if numeric:
        # A number compared with a substring operator is not the same
        # comparison, so an unanchored numeric pattern is not translated.
        return None
    if starts:
        return _Condition(s1ql_field, "StartsWithCIS", core)
    if ends:
        return _Condition(s1ql_field, "EndsWithCIS", core)
    return _Condition(s1ql_field, "ContainsCIS", core)


def _unescape(pattern: str) -> str | None:
    """Return the literal text of a pattern, or None if it is not literal.

    This is the whole safety property of the compiler: anything that still
    carries regex meaning after unescaping cannot be expressed as an S1QL
    string comparison, so it declines instead of approximating.
    """
    literal: list[str] = []
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "\\":
            if index + 1 >= len(pattern):
                return None
            following = pattern[index + 1]
            if following not in _LITERAL_ESCAPES:
                return None
            literal.append(following)
            index += 2
            continue
        if character in _UNTRANSLATABLE or character in "^$":
            return None
        literal.append(character)
        index += 1
    return "".join(literal)


def _rule_level(rule: ElementTree.Element) -> int:
    try:
        return int((rule.get("level") or "").strip())
    except ValueError:
        return 0


def _severity_for(level: int) -> str:
    for threshold, severity in _SEVERITY_BANDS:
        if level >= threshold:
            return severity
    return "Low"


def _text_of(rule: ElementTree.Element, tag: str) -> str:
    element = rule.find(tag)
    if element is None or element.text is None:
        return ""
    return " ".join(element.text.split())


def _rule_name(pattern: ProvenMitigationPattern, rule: ElementTree.Element) -> str:
    rule_id = (rule.get("id") or "").strip()
    suffix = f"-{rule_id}" if rule_id else ""
    return f"JANUS-{pattern.vulnerability_id}{suffix}"


def is_wazuh_rule_artifact(artifact_type: str | None) -> bool:
    """Whether the upstream candidate declared itself a Wazuh rule."""
    return (artifact_type or "").strip().lower() == WAZUH_ARTIFACT_TYPE
