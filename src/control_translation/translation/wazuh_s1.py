"""Deterministic Wazuh rule -> SentinelOne STAR rule compilation.

The Defense Generation candidate names what it produced in `artifact_type`.
When that is `wazuh-rule`, the authoritative artifact is a Wazuh XML rule and
the target is SentinelOne, so the candidate is compiled here in code rather
than proposed by a model -- the same posture the ModSecurity -> Akamai path
takes, and for the same reason: the upstream artifact is executable and
authoritative, so guessing at it is worse than declining.

The vocabulary below is the producer's, not Wazuh's whole surface. Defense
Generation emits a fixed set of canonical observables (`event.type`,
`src.process.*`, `tgt.file.path`, `registry.keyPath`, ...) with
`type="pcre2"`, as in `tests/fixtures/defense-generation-wazuh-candidate.xml`.
A generic Sysmon or auditd ruleset uses different field names and is not what
this reads.

Everything here fails closed. A Wazuh rule is a conjunction of conditions, so
any condition this cannot express exactly -- a negated field, a correlation
across events, a regex that is not a literal with anchors, a condition element
outside the `<field>` vocabulary -- makes the whole rule undecidable rather
than partially translated. Dropping a condition broadens a detection and
inverting one reverses it; both are worse than declining.

What this cannot do is pretend the two products see the same thing. A Wazuh
rule matches decoded *log events*; an S1QL query matches *endpoint telemetry*.
The STAR shape is the `POST /web/api/v2.1/cloud-detection/rules` body described
in `docs/syntexresearch.md`; it has not been validated against a live console.
"""

from __future__ import annotations

import xml.etree.ElementTree as ElementTree

from control_translation.agents.translation_agent import TranslationProposal
from control_translation.contracts import ProvenMitigationPattern

# The artifact_type a Defense Generation candidate uses for a Wazuh rule.
WAZUH_ARTIFACT_TYPE = "wazuh-rule"

# The field that carries the event class. It is not a comparison like the
# others: its value becomes the S1QL EventType and decides which other
# observables can appear at all.
EVENT_TYPE_FIELD = "event.type"

# SentinelOne EventType values this can emit, and the observable family each
# belongs to. An event.type outside this set declines: passing an unrecognized
# value through would produce a syntactically valid rule that never fires,
# which is the one failure mode a detection cannot report.
_EVENT_FAMILIES: dict[str, str] = {
    "Process Creation": "process",
    "File Creation": "file",
    "File Modification": "file",
    "File Deletion": "file",
    "Registry Key Create": "registry",
    "Registry Value Create": "registry",
    "Registry Value Modified": "registry",
    "IP Connect": "network",
}

# Producer observable -> (S1QL field, the event families where it is observable).
#
# SrcProc* is the acting process for a Process Creation event in both dialects:
# the producer's telemetry puts the executed command line in
# `src.process.cmdline`, and the S1QL example in docs/syntexresearch.md matches
# the same thing with SrcProcCmdLine. Getting that round the wrong way would
# build a rule about the parent process instead.
_FIELD_MAP: dict[str, tuple[str, frozenset[str]]] = {
    "src.process.name": ("SrcProcName", frozenset({"process"})),
    "src.process.cmdline": ("SrcProcCmdLine", frozenset({"process"})),
    "tgt.file.path": ("TgtFilePath", frozenset({"file"})),
    "registry.keypath": ("RegistryKeyPath", frozenset({"registry"})),
}

# Producer observables with no SentinelOne counterpart this can name. They are
# listed rather than merely absent so the decline says which observable stopped
# it instead of reporting an unknown field.
_UNMAPPED_OBSERVABLES: dict[str, str] = {
    "script.content": (
        "SentinelOne Deep Visibility has no script-content observable that "
        "this can name; matching the interpreter command line instead would "
        "detect something different"
    ),
}

# Wazuh matching engines whose "^" and "$" anchor. "osmatch" is a plain
# substring match where both are literal characters, so the anchor handling
# below would silently change what the rule means.
_REGEX_ENGINES = frozenset({"pcre2", "osregex", ""})

# Rule attributes that make a rule a correlation over several events. One STAR
# query matches one event, so these cannot be expressed.
_CORRELATION_ATTRIBUTES = ("frequency", "timeframe")

# Condition-bearing elements other than <field>. Each one narrows the rule, so
# any of them present means the field conditions alone are not the rule.
_UNSUPPORTED_CONDITIONS = frozenset({
    "decoded_as", "program_name", "match", "regex", "pcre2",
    "srcip", "dstip", "srcport", "dstport", "user", "srcuser", "dstuser",
    "url", "id", "status", "hostname", "extra_data", "system_name",
    "action", "location", "data", "protocol",
    "if_sid", "if_group", "if_matched_sid", "if_matched_group",
    "same_source_ip", "same_srcip", "same_user", "different_url",
})

# Elements that carry no condition.
_METADATA_ELEMENTS = frozenset({"description", "group", "options", "info", "list", "mitre"})

# Regex constructs that are not a literal. A bare "." is here on purpose: in a
# pattern it matches any character, so treating it as a literal dot narrows the
# rule. A literal dot is written "\." and is unescaped below.
_UNTRANSLATABLE = frozenset("*+?[]{}()|.")

# Backslash escapes denoting a literal character; unescaping them loses
# nothing. Anything else after a backslash ("\d", "\w", "\s") is a character
# class with no S1QL equivalent.
_LITERAL_ESCAPES = frozenset(".\\-/@:^$ _")

# Wazuh level (0-15) to the four STAR severities.
_SEVERITY_BANDS = ((12, "Critical"), (9, "High"), (6, "Medium"), (0, "Low"))


class DeclinedRule(Exception):
    """A rule this cannot express exactly, carrying why."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _Comparison:
    """One S1QL comparison derived from one Wazuh field."""

    def __init__(self, field: str, operator: str, value: str) -> None:
        self.field = field
        self.operator = operator
        self.value = value

    def render(self) -> str:
        escaped = self.value.replace("\\", "\\\\").replace("'", "\\'")
        return f"{self.field} {self.operator} '{escaped}'"


def compile_sentinelone_star_rule(
    pattern: ProvenMitigationPattern,
) -> TranslationProposal | None:
    """Compile the proven Wazuh rule into a STAR rule, or return None.

    None means the rule uses something this cannot express faithfully; the
    caller then declines rather than falling back to a guess.
    """
    try:
        return _compile(pattern)
    except DeclinedRule:
        return None


def decline_reason(pattern: ProvenMitigationPattern) -> str | None:
    """Why the rule could not be compiled, for the decline detail."""
    try:
        _compile(pattern)
    except DeclinedRule as declined:
        return declined.reason
    return None


def _compile(pattern: ProvenMitigationPattern) -> TranslationProposal:
    rule = _parse_rule(pattern.pattern_summary)
    _reject_unsupported_structure(rule)

    event_type, comparisons = _read_fields(rule)
    if event_type is None:
        raise DeclinedRule(
            f"the rule declares no {EVENT_TYPE_FIELD}, so the SentinelOne "
            "event class it applies to is unknown"
        )
    if not comparisons:
        raise DeclinedRule(
            f"the rule constrains only {EVENT_TYPE_FIELD}, which would match "
            "every event of that class"
        )

    family = _EVENT_FAMILIES[event_type]
    for observable, comparison in comparisons:
        _, families = _FIELD_MAP[observable]
        if family not in families:
            raise DeclinedRule(
                f"'{observable}' is not observable on a '{event_type}' event, "
                "so the compiled query could never match"
            )

    clauses = [f"EventType = '{event_type}'"]
    clauses.extend(comparison.render() for _, comparison in comparisons)

    star_rule = {
        "data": {
            "name": _rule_name(pattern, rule),
            "description": _text_of(rule, "description")
            or pattern.discriminator_description,
            "severity": _severity_for(_rule_level(rule)),
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

    translated = ", ".join(
        f"{observable} -> {comparison.field}"
        for observable, comparison in comparisons
    )
    return TranslationProposal(
        candidate_content=star_rule,
        # Every condition was translated exactly or the rule declined, so the
        # query matches what the Wazuh rule matches.
        translation_label="equivalent",
        justification=(
            "Compiled the proven Wazuh rule deterministically into a "
            f"SentinelOne STAR rule over {event_type} events: {translated}."
        ),
        translation_assumptions=[
            "The Wazuh rule in the upstream defense-generation artifact is the "
            "authoritative source of the match semantics.",
            "The canonical observables the rule names are the same activity "
            "SentinelOne records independently on the endpoint, so a condition "
            "on one holds for the other.",
            "S1QL's CIS operators are case-insensitive and their plain forms "
            "are case-sensitive, which is how a pattern's (?i) flag is carried "
            "across; the console is not reachable from here to confirm it.",
            "Backslashes in a path are doubled inside the S1QL string literal.",
            "The STAR rule is scoped at creation time; no account, site or "
            "group filter is asserted here.",
        ],
        limitations=[
            "The candidate is shape-validated only and has not been created in "
            "a SentinelOne console.",
            "Wazuh matches decoded log events and S1QL matches endpoint "
            "telemetry; the two observe the same activity through different "
            "collectors, so timing and field coverage are not identical.",
            "treatAsThreat is UNDEFINED, so the rule alerts without killing or "
            "quarantining. Promoting it is an operator decision.",
        ],
    )


def _reject_unsupported_structure(rule: ElementTree.Element) -> None:
    """Fail closed on anything outside the <field> vocabulary.

    A Wazuh rule ANDs all of its conditions. Ignoring one because this cannot
    read it makes the emitted query match more than the rule does, so an
    unreadable condition ends the compilation instead.
    """
    for attribute in _CORRELATION_ATTRIBUTES:
        if (rule.get(attribute) or "").strip():
            raise DeclinedRule(
                f"the rule correlates across events via '{attribute}', which a "
                "single STAR query cannot express"
            )

    for element in rule:
        tag = element.tag
        if tag == "field" or tag in _METADATA_ELEMENTS:
            continue
        if tag in _UNSUPPORTED_CONDITIONS:
            raise DeclinedRule(
                f"the rule uses the '<{tag}>' condition, which this does not "
                "translate; dropping it would broaden the detection"
            )
        raise DeclinedRule(
            f"the rule uses an unrecognized element '<{tag}>', so what it "
            "matches cannot be established"
        )


def _read_fields(
    rule: ElementTree.Element,
) -> tuple[str | None, list[tuple[str, _Comparison]]]:
    event_type: str | None = None
    comparisons: list[tuple[str, _Comparison]] = []

    for element in rule.findall("field"):
        name = (element.get("name") or "").strip().lower()
        if not name:
            raise DeclinedRule("a <field> condition has no name")

        # A negated condition is the one case where a partial translation is
        # worse than none: emitted positively it matches exactly what the rule
        # excludes.
        if (element.get("negate") or "").strip().lower() in ("yes", "true", "1"):
            raise DeclinedRule(
                f"'{name}' is negated, and S1QL negation is not translated "
                "here; emitting it positively would reverse the rule"
            )

        engine = (element.get("type") or "").strip().lower()
        if engine not in _REGEX_ENGINES:
            raise DeclinedRule(
                f"'{name}' uses the '{engine}' matching engine, where the "
                "anchors this relies on do not mean what they mean in a regex"
            )

        value = (element.text or "").strip()
        if not value:
            raise DeclinedRule(f"'{name}' has no pattern to match")

        if name == EVENT_TYPE_FIELD:
            event_type = _read_event_type(value)
            continue
        if name in _UNMAPPED_OBSERVABLES:
            raise DeclinedRule(
                f"'{name}' cannot be translated: {_UNMAPPED_OBSERVABLES[name]}"
            )
        mapped = _FIELD_MAP.get(name)
        if mapped is None:
            raise DeclinedRule(
                f"'{name}' is not in the observable vocabulary this translates; "
                "dropping it would broaden the detection"
            )
        comparisons.append((name, _comparison_for(mapped[0], name, value)))

    return event_type, comparisons


def _read_event_type(value: str) -> str:
    """Read the S1 EventType from an event.type pattern.

    The producer writes it anchored, as "^Process Creation$". Anything less
    exact would leave the event class ambiguous.
    """
    pattern, case_insensitive = _strip_inline_flags(value)
    if not (pattern.startswith("^") and _ends_anchored(pattern)):
        raise DeclinedRule(
            f"{EVENT_TYPE_FIELD} must be an anchored exact pattern; "
            "an unanchored event class is ambiguous"
        )
    literal = _unescape(pattern[1:-1])
    if literal is None:
        raise DeclinedRule(f"{EVENT_TYPE_FIELD} is not a literal event class")

    for known in _EVENT_FAMILIES:
        if literal == known or (case_insensitive and literal.lower() == known.lower()):
            return known
    raise DeclinedRule(
        f"'{literal}' is not a SentinelOne event class this recognizes, so the "
        "compiled query would never match"
    )


def _comparison_for(s1ql_field: str, observable: str, raw: str) -> _Comparison:
    """Translate one field pattern into an S1QL comparison.

    Only anchors and the inline case-insensitivity flag are translated, because
    those map exactly onto S1QL operators. Any other regex construct declines.
    """
    pattern, case_insensitive = _strip_inline_flags(raw)

    starts = pattern.startswith("^")
    body = pattern[1:] if starts else pattern
    ends = _ends_anchored(body)
    body = body[:-1] if ends else body

    literal = _unescape(body)
    if literal is None:
        raise DeclinedRule(
            f"the pattern for '{observable}' is a regex, and S1QL compares "
            "strings; approximating it would change what the rule matches"
        )
    if not literal:
        raise DeclinedRule(f"the pattern for '{observable}' matches nothing")

    if starts and ends:
        if case_insensitive:
            # S1QL equality is case-sensitive and this has no case-insensitive
            # equality operator it can vouch for, so the combination declines
            # rather than being widened to a substring match.
            raise DeclinedRule(
                f"the pattern for '{observable}' is a case-insensitive exact "
                "match, which this does not translate"
            )
        return _Comparison(s1ql_field, "=", literal)

    suffix = "CIS" if case_insensitive else ""
    if starts:
        return _Comparison(s1ql_field, f"StartsWith{suffix}", literal)
    if ends:
        return _Comparison(s1ql_field, f"EndsWith{suffix}", literal)
    return _Comparison(s1ql_field, f"Contains{suffix}", literal)


def _strip_inline_flags(pattern: str) -> tuple[str, bool]:
    """Split a leading "(?i)" off a pattern.

    It is the one inline flag with an exact S1QL counterpart: the CIS operators
    are case-insensitive. Any other inline group is left in place and will be
    rejected as a regex construct.
    """
    if pattern.startswith("(?i)"):
        return pattern[4:], True
    return pattern, False


def _ends_anchored(pattern: str) -> bool:
    """Whether a pattern ends with an anchoring "$" rather than a literal one."""
    if not pattern.endswith("$"):
        return False
    # Count the backslashes immediately before it: an odd number escapes it.
    trailing = len(pattern[:-1]) - len(pattern[:-1].rstrip("\\"))
    return trailing % 2 == 0


def _unescape(pattern: str) -> str | None:
    """Return the literal text of a pattern, or None if it is not literal.

    This is the safety property of the compiler: anything still carrying regex
    meaning after unescaping cannot be an S1QL string comparison, so it
    declines instead of being approximated.
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


def _parse_rule(artifact: str) -> ElementTree.Element:
    """Return the single <rule> element, declining anything else."""
    text = (artifact or "").strip()
    if not text:
        raise DeclinedRule("the artifact is empty")
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        raise DeclinedRule(f"the artifact is not well-formed XML: {exc}") from exc

    if root.tag == "rule":
        return root
    rules = root.findall(".//rule")
    if not rules:
        raise DeclinedRule("the artifact contains no <rule>")
    if len(rules) > 1:
        # The proof loop validated one candidate, not a rule set.
        raise DeclinedRule(
            f"the artifact contains {len(rules)} rules; one proven candidate "
            "is expected"
        )
    return rules[0]


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
