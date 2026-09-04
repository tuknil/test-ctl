"""Deterministic ModSecurity -> Akamai custom WAF rule compiler.

This is the default execution path for `akamai-waf` translation. The proven
mitigation pattern's `pattern_summary` carries the authoritative
defense-generation artifact, which is a ModSecurity `SecRule`. This module
compiles that rule mechanically into the Akamai Application Security
custom-rule JSON shape documented in `docs/syntexresearch.md`
(`operation` + `conditions[]`), so a translation that code can derive is
never delegated to a model.

The compiler is deliberately conservative. Any construct whose Akamai
equivalent is not known with certainty makes it decline (return `None`), and
`translation/engine.py` falls back to the translation doer (fixture or live
LLM). Output is still untrusted: it passes the same adapter syntax gate and
conflict gate as any doer proposal.

Note: the rule action is assigned when the custom rule is bound to a security
policy, so the compiled body never embeds `deny`/`alert` even though the
source `SecRule` does.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote, quote_plus

from control_translation.agents.translation_agent import TranslationProposal
from control_translation.contracts import (
    ProofLoopTranslationRequirements,
    ProvenMitigationPattern,
)

# Bounds. A proven pattern is small; anything larger is a sign the source is
# not the single virtual-patch rule this path is designed for.
_MAX_RULES = 8
_MAX_VALUES = 32
_MAX_CLASS_MEMBERS = 8
_MAX_REGEX_LENGTH = 4096
_MAX_ARGUMENT_LENGTH = 4096

_SECRULE_LINE = re.compile(r"^\s*SecRule\b", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Request-component mapping
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Component:
    """How one ModSecurity collection maps onto an Akamai condition."""

    condition_type: str
    label: str
    selector_key: str | None
    encodable: bool
    literal_only: bool = False
    coverage_note: str | None = None


_ARGS_COVERAGE_NOTE = (
    "ModSecurity ARGS covers query-string and request-body arguments; the "
    "Akamai candidate matches POST body arguments only. Add an equivalent "
    "uriQueryMatch condition if the endpoint also accepts this parameter in "
    "the query string."
)
_URI_COVERAGE_NOTE = (
    "ModSecurity REQUEST_URI includes the query string; pathMatch inspects "
    "the URI path only."
)

_COMPONENTS: dict[str, _Component] = {
    "ARGS": _Component(
        "argsPostMatch", "POST argument", "parameter", True,
        coverage_note=_ARGS_COVERAGE_NOTE,
    ),
    "ARGS_POST": _Component("argsPostMatch", "POST argument", "parameter", True),
    "ARGS_GET": _Component("uriQueryMatch", "query string", None, True),
    "QUERY_STRING": _Component("uriQueryMatch", "query string", None, True),
    "REQUEST_BODY": _Component("argsPostMatch", "request body", None, True),
    "XML": _Component("argsPostXMLMatch", "XML request body", None, False),
    "REQUEST_HEADERS": _Component(
        "requestHeaderValueMatch", "request header", "header", False
    ),
    "REQUEST_URI": _Component(
        "pathMatch", "request path", None, True, coverage_note=_URI_COVERAGE_NOTE
    ),
    "REQUEST_URI_RAW": _Component(
        "pathMatch", "request path", None, True, coverage_note=_URI_COVERAGE_NOTE
    ),
    "REQUEST_FILENAME": _Component("pathMatch", "request path", None, True),
    "REQUEST_COOKIES": _Component("cookieMatch", "cookie", "name", False),
    "REQUEST_METHOD": _Component(
        "requestMethodMatch", "request method", None, False, literal_only=True
    ),
    "REMOTE_ADDR": _Component(
        "ipMatch", "client IP", None, False, literal_only=True
    ),
}

# Collections that carry a header name in the Akamai condition. Without a
# selector, Akamai's documented type for "any request header" is
# requestHeaderMatch, which takes no `header` key.
_ANY_HEADER_CONDITION = "requestHeaderMatch"

# Components whose values feed the required-payload merge for bypass-driven
# translation requirements.
_BODY_CONDITIONS = frozenset({"argsPostMatch", "argsPostJSONMatch", "argsPostXMLMatch"})


# ---------------------------------------------------------------------------
# SecRule parsing
# ---------------------------------------------------------------------------


class _Unsupported(Exception):
    """The source construct has no certain Akamai equivalent."""


@dataclass(frozen=True)
class _Variable:
    collection: str
    selector: str | None


@dataclass(frozen=True)
class _SecRule:
    variables: tuple[_Variable, ...]
    negated: bool
    operator: str
    argument: str
    transformations: tuple[str, ...]
    message: str | None
    tags: tuple[str, ...]
    chained: bool


def _split_directives(text: str) -> list[str]:
    """Join ModSecurity line continuations and return SecRule directives."""
    joined: list[str] = []
    buffer = ""
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if line.endswith("\\"):
            buffer += line[:-1].rstrip() + " "
            continue
        buffer += line
        if buffer.strip():
            joined.append(buffer.strip())
        buffer = ""
    if buffer.strip():
        joined.append(buffer.strip())
    return [line for line in joined if _SECRULE_LINE.match(line)]


def _tokenize(directive: str) -> list[str]:
    """Split a SecRule directive into its quoted/unquoted argument tokens."""
    body = directive.strip()[len("SecRule"):]
    tokens: list[str] = []
    index = 0
    length = len(body)
    while index < length:
        while index < length and body[index].isspace():
            index += 1
        if index >= length:
            break
        if body[index] == '"':
            index += 1
            chunk: list[str] = []
            while index < length and body[index] != '"':
                if body[index] == "\\" and index + 1 < length:
                    following = body[index + 1]
                    # ModSecurity only needs \" and \\ unescaped here; every
                    # other backslash belongs to the regex itself.
                    if following in ('"', "\\"):
                        chunk.append(following)
                        index += 2
                        continue
                chunk.append(body[index])
                index += 1
            if index >= length:
                raise _Unsupported("unterminated quoted token")
            index += 1
            tokens.append("".join(chunk))
        else:
            start = index
            while index < length and not body[index].isspace():
                index += 1
            tokens.append(body[start:index])
    return tokens


def _split_actions(actions: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quote_char: str | None = None
    for char in actions:
        if quote_char is not None:
            if char == quote_char:
                quote_char = None
            else:
                current.append(char)
            continue
        if char in ("'", '"'):
            quote_char = char
            continue
        if char == ",":
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    parts.append("".join(current).strip())
    return [part for part in parts if part]


def _parse_variables(token: str) -> tuple[_Variable, ...]:
    variables: list[_Variable] = []
    for raw in token.split("|"):
        item = raw.strip()
        if not item:
            raise _Unsupported("empty variable")
        if item.startswith("!"):
            raise _Unsupported("variable exclusions are not expressible")
        collection, _, selector = item.partition(":")
        collection = collection.strip().upper()
        selector = selector.strip().strip("'\"")
        if selector.startswith("/") or "*" in selector:
            raise _Unsupported("regex variable selectors are not expressible")
        variables.append(_Variable(collection, selector or None))
    if not variables:
        raise _Unsupported("no variables")
    return tuple(variables)


def _parse_secrule(directive: str) -> _SecRule:
    tokens = _tokenize(directive)
    if len(tokens) < 2:
        raise _Unsupported("SecRule needs a variable and an operator")
    variables = _parse_variables(tokens[0])

    operator_token = tokens[1].strip()
    negated = operator_token.startswith("!")
    if negated:
        operator_token = operator_token[1:].lstrip()
    if not operator_token.startswith("@"):
        # An implicit operator means the token is raw regex. Refusing it keeps
        # prose and malformed producer output out of this path.
        raise _Unsupported("SecRule operator must be explicit (@rx, @contains, ...)")
    operator, _, argument = operator_token[1:].partition(" ")
    operator = operator.strip()
    argument = argument.strip()
    if len(argument) > _MAX_ARGUMENT_LENGTH:
        raise _Unsupported("operator argument is too large")

    transformations: list[str] = []
    message: str | None = None
    tags: list[str] = []
    chained = False
    for action in _split_actions(tokens[2] if len(tokens) > 2 else ""):
        name, _, value = action.partition(":")
        name = name.strip().lower()
        value = value.strip()
        if name == "t":
            transformations.append(value.lower())
        elif name == "msg":
            message = value or None
        elif name == "tag":
            if value:
                tags.append(value)
        elif name == "chain":
            chained = True
    return _SecRule(
        variables=variables,
        negated=negated,
        operator=operator,
        argument=argument,
        transformations=tuple(transformations),
        message=message,
        tags=tuple(tags),
        chained=chained,
    )


# ---------------------------------------------------------------------------
# Regex -> Akamai wildcard values
# ---------------------------------------------------------------------------

_ANY = ("any",)
_ONE = ("one",)

_CLASS_SHORTHAND = frozenset("sSdDwW")
_ESCAPE_LITERALS = {"n": "\n", "r": "\r", "t": "\t", "f": "\f", "v": "\v"}


@dataclass
class _RegexResult:
    values: list[str]
    wildcard: bool
    case_insensitive: bool
    # lossy marks a generalization that can match MORE than the source.
    lossy: bool
    # narrowed marks encoding-ladder alignment, which matches LESS: only
    # uniformly encoded values, not every mixed-depth combination.
    narrowed: bool = False


class _RegexTranslator:
    """Expand a bounded regex subset into Akamai wildcard match values.

    Akamai string conditions match literals with `*` (any run) and `?` (one
    character) when `valueWildcard` is set, so only regex constructs with a
    faithful wildcard image are accepted. Everything else raises
    `_Unsupported` and the caller falls back to the doer.
    """

    def __init__(self, source: str) -> None:
        self.source = source
        self.index = 0
        self.lossy = False
        self.narrowed = False
        self.case_insensitive = False

    def translate(self) -> _RegexResult:
        if len(self.source) > _MAX_REGEX_LENGTH:
            raise _Unsupported("regex is too large")
        self._read_inline_flags()
        anchored_start = False
        anchored_end = False
        if self.source.startswith("^", self.index):
            anchored_start = True
            self.index += 1
        body = self.source[self.index:]
        if body.endswith("$") and not body.endswith("\\$"):
            anchored_end = True
            body = body[:-1]
        self.source = body
        self.index = 0

        alternatives = self._parse_alternation(depth=0)
        if self.index != len(self.source):
            raise _Unsupported("unbalanced regex group")

        depths = _ladder_depth(alternatives)
        if depths is None:
            raise _Unsupported("encoding ladders of differing depths cannot be aligned")

        wildcard = not anchored_start or not anchored_end
        values: list[str] = []
        # One value per encoding depth, with every ladder rendered at that same
        # depth: the combinations a uniformly encoded value actually produces.
        for depth in range(depths):
            for parts in alternatives:
                rendered, used_wildcard = _render(parts, depth)
                wildcard = wildcard or used_wildcard
                if not anchored_start:
                    rendered = "*" + rendered
                if not anchored_end:
                    rendered = rendered + "*"
                values.append(rendered)
        values = _unique(values)
        if len(values) > _MAX_VALUES:
            raise _Unsupported("regex expands to too many values")
        if not values or any(not value for value in values):
            raise _Unsupported("regex produced an empty match value")
        if wildcard and any(
            _has_literal_wildcard(parts) for parts in alternatives
        ):
            raise _Unsupported("literal '*' or '?' cannot coexist with wildcards")
        return _RegexResult(
            values=values,
            wildcard=wildcard,
            case_insensitive=self.case_insensitive,
            lossy=self.lossy,
            narrowed=self.narrowed,
        )

    def _read_inline_flags(self) -> None:
        match = re.match(r"\(\?([a-zA-Z]+)\)", self.source)
        if match is None:
            return
        flags = match.group(1)
        if set(flags) - set("is"):
            raise _Unsupported(f"unsupported inline regex flags: {flags}")
        self.case_insensitive = "i" in flags
        self.index = match.end()

    # -- recursive descent -------------------------------------------------

    def _parse_alternation(self, depth: int) -> list[list[tuple]]:
        if depth > 8:
            raise _Unsupported("regex nesting is too deep")
        alternatives = self._parse_concat(depth)
        while self.index < len(self.source) and self.source[self.index] == "|":
            self.index += 1
            alternatives.extend(self._parse_concat(depth))
            if len(alternatives) > _MAX_VALUES:
                raise _Unsupported("regex expands to too many values")
        return alternatives

    def _parse_concat(self, depth: int) -> list[list[tuple]]:
        results: list[list[tuple]] = [[]]
        while self.index < len(self.source) and self.source[self.index] not in "|)":
            term = self._parse_term(depth)
            combined: list[list[tuple]] = []
            for prefix in results:
                for suffix in term:
                    combined.append(prefix + suffix)
            if len(combined) > _MAX_VALUES:
                raise _Unsupported("regex expands to too many values")
            results = combined
        return results

    def _parse_term(self, depth: int) -> list[list[tuple]]:
        alternatives, single_char = self._parse_atom(depth)
        if self.index >= len(self.source) or self.source[self.index] not in "*+?":
            return alternatives
        quantifier = self.source[self.index]
        self.index += 1
        if self.index < len(self.source) and self.source[self.index] in "?+":
            self.index += 1  # lazy / possessive marker
        if not single_char:
            raise _Unsupported("quantified groups are not expressible")
        if quantifier == "+":
            # Keep one concrete occurrence, then allow the repetition.
            expanded = [parts + [_ANY] for parts in alternatives]
        else:
            expanded = [[_ANY]]
        if any(part[0] == "ladder" for parts in alternatives for part in parts):
            raise _Unsupported("quantified encoding ladders are not expressible")
        if alternatives != [[_ONE]]:
            # Quantifying '.' keeps full fidelity; quantifying a literal or an
            # enumerated class widens the match.
            self.lossy = True
        return expanded

    def _parse_atom(self, depth: int) -> tuple[list[list[tuple]], bool]:
        char = self.source[self.index]
        if char == "(":
            if self.source.startswith("(?", self.index) and not self.source.startswith(
                "(?:", self.index
            ):
                raise _Unsupported("lookarounds and inline groups are not expressible")
            self.index += 3 if self.source.startswith("(?:", self.index) else 1
            alternatives = self._parse_alternation(depth + 1)
            if self.index >= len(self.source) or self.source[self.index] != ")":
                raise _Unsupported("unbalanced regex group")
            self.index += 1
            ladder = _as_encoding_ladder(alternatives)
            if ladder is not None:
                self.narrowed = True
                return [[("ladder", ladder)]], False
            single = all(len(parts) == 1 for parts in alternatives)
            return alternatives, single
        if char == "[":
            return self._parse_class(), True
        if char == "\\":
            return self._parse_escape()
        if char == ".":
            self.index += 1
            return [[_ONE]], True
        if char in "^$":
            raise _Unsupported("anchors are only supported at the pattern edges")
        if char in "{}":
            raise _Unsupported("counted repetition is not expressible")
        self.index += 1
        return [[("lit", char)]], True

    def _parse_class(self) -> list[list[tuple]]:
        end = self.source.find("]", self.index + 1)
        if end == -1:
            raise _Unsupported("unterminated character class")
        body = self.source[self.index + 1 : end]
        self.index = end + 1
        if body.startswith("^") or not body:
            self.lossy = True
            return [[_ONE]]
        members = _enumerate_class(body)
        if members is None or len(members) > _MAX_CLASS_MEMBERS:
            self.lossy = True
            return [[_ONE]]
        return [[("lit", member)] for member in members]

    def _parse_escape(self) -> tuple[list[list[tuple]], bool]:
        if self.index + 1 >= len(self.source):
            raise _Unsupported("dangling escape")
        char = self.source[self.index + 1]
        self.index += 2
        if char in _CLASS_SHORTHAND:
            self.lossy = True
            return [[_ONE]], True
        if char in ("b", "B"):
            # Word boundaries have no wildcard image; dropping them widens the
            # match, which is recorded as a limitation by the caller.
            self.lossy = True
            return [[]], False
        if char in _ESCAPE_LITERALS:
            return [[("lit", _ESCAPE_LITERALS[char])]], True
        if char == "x":
            hex_digits = self.source[self.index : self.index + 2]
            if len(hex_digits) != 2 or not re.fullmatch(r"[0-9A-Fa-f]{2}", hex_digits):
                raise _Unsupported("unsupported hexadecimal escape")
            self.index += 2
            return [[("lit", chr(int(hex_digits, 16)))]], True
        if char.isalnum():
            raise _Unsupported(f"unsupported regex escape: \\{char}")
        return [[("lit", char)]], True


def _enumerate_class(body: str) -> list[str] | None:
    members: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\":
            if index + 1 >= len(body):
                return None
            following = body[index + 1]
            if following in _CLASS_SHORTHAND or following.isalnum():
                if following not in _ESCAPE_LITERALS:
                    return None
                members.append(_ESCAPE_LITERALS[following])
            else:
                members.append(following)
            index += 2
            continue
        if index + 2 < len(body) and body[index + 1] == "-":
            start, stop = ord(char), ord(body[index + 2])
            if stop < start or stop - start >= _MAX_CLASS_MEMBERS:
                return None
            members.extend(chr(code) for code in range(start, stop + 1))
            index += 3
            continue
        members.append(char)
        index += 1
    return _unique(members) if members else None


def _render(parts: list[tuple], depth: int = 0) -> tuple[str, bool]:
    rendered: list[str] = []
    used_wildcard = False
    for part in parts:
        if part[0] == "ladder":
            rendered.append(part[1][depth])
        elif part == _ANY:
            used_wildcard = True
            if rendered and rendered[-1] == "*":
                continue
            rendered.append("*")
        elif part == _ONE:
            used_wildcard = True
            rendered.append("?")
        else:
            rendered.append(part[1])
    return "".join(rendered), used_wildcard


def _as_encoding_ladder(alternatives: list[list[tuple]]) -> tuple[str, ...] | None:
    """Return a group's branches in depth order when it is an encoding ladder.

    Defense generation enumerates recursive URL-encodings of one character per
    group, e.g. ``(?:\[|%5B|%255B|%25255B)``. Expanding several such groups
    positionally is a cross-product that explodes, because it enumerates values
    whose characters were each encoded a different number of times. Real
    traffic encodes a value at one depth, so the caller emits one value per
    depth instead. Returns None when the group is an ordinary alternation.
    """
    if len(alternatives) < 2:
        return None
    branches: list[str] = []
    for parts in alternatives:
        if not parts or any(part[0] != "lit" for part in parts):
            return None
        branches.append("".join(part[1] for part in parts))
    if any(
        branches[index] != quote(branches[index - 1], safe="")
        for index in range(1, len(branches))
    ):
        return None
    return tuple(branches)


def _ladder_depth(alternatives: list[list[tuple]]) -> int | None:
    """Return the depth every ladder shares, 1 when there is none, or None.

    None means the alternatives hold ladders of differing lengths, which have
    no single depth to align on; the caller declines rather than guessing which
    depths pair up.
    """
    depth = 0
    for parts in alternatives:
        for part in parts:
            if part[0] != "ladder":
                continue
            if depth == 0:
                depth = len(part[1])
            elif depth != len(part[1]):
                return None
    return depth or 1


def _has_literal_wildcard(parts: list[tuple]) -> bool:
    return any(part[0] == "lit" and part[1] in ("*", "?") for part in parts)


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


# ---------------------------------------------------------------------------
# Operator -> match values
# ---------------------------------------------------------------------------


@dataclass
class _Match:
    values: list[str]
    wildcard: bool
    case_insensitive: bool
    lossy: bool
    narrowed: bool = False


def _literal(value: str) -> str:
    if not value:
        raise _Unsupported("empty operator argument")
    return value


def _operator_match(rule: _SecRule) -> _Match:
    operator = rule.operator
    argument = rule.argument
    if operator == "rx":
        result = _RegexTranslator(argument).translate()
        return _Match(
            values=result.values,
            wildcard=result.wildcard,
            case_insensitive=result.case_insensitive,
            lossy=result.lossy,
            narrowed=result.narrowed,
        )
    if operator == "contains":
        return _Match([f"*{_literal(argument)}*"], True, False, False)
    if operator == "beginsWith":
        return _Match([f"{_literal(argument)}*"], True, False, False)
    if operator == "endsWith":
        return _Match([f"*{_literal(argument)}"], True, False, False)
    if operator in ("streq", "eq"):
        return _Match([_literal(argument)], False, False, False)
    if operator == "within":
        members = _unique([item for item in argument.split() if item])
        if not members:
            raise _Unsupported("empty @within list")
        return _Match(members, False, False, False)
    if operator == "pm":
        members = _unique([item for item in argument.split() if item])
        if not members:
            raise _Unsupported("empty @pm list")
        if len(members) > _MAX_VALUES:
            raise _Unsupported("@pm list is too large")
        return _Match([f"*{item}*" for item in members], True, True, False)
    if operator == "ipMatch":
        members = _unique(
            [item.strip() for item in re.split(r"[,\s]+", argument) if item.strip()]
        )
        if not members:
            raise _Unsupported("empty @ipMatch list")
        return _Match(members, False, False, False)
    raise _Unsupported(f"unsupported ModSecurity operator: @{operator}")


def _encoding_variants(values: list[str]) -> list[str]:
    """Add the transport encodings an edge WAF may observe for a literal."""
    variants: list[str] = []
    for value in values:
        encoded_once = quote(value, safe="")
        variants.extend(
            (
                value,
                encoded_once,
                quote_plus(value, safe=""),
                quote(encoded_once, safe=""),
            )
        )
    return _unique(variants)


# ---------------------------------------------------------------------------
# Condition assembly
# ---------------------------------------------------------------------------


@dataclass
class _CompiledCondition:
    condition: dict
    notes: list[str]
    lossy: bool
    narrowed: bool = False


def _build_condition(
    variable: _Variable,
    rule: _SecRule,
    match: _Match,
    *,
    case_sensitive: bool,
) -> _CompiledCondition:
    component = _COMPONENTS.get(variable.collection)
    if component is None:
        raise _Unsupported(f"unsupported ModSecurity collection: {variable.collection}")
    if component.selector_key == "header" and variable.selector is None:
        condition_type = _ANY_HEADER_CONDITION
    else:
        condition_type = component.condition_type
    if component.literal_only and match.wildcard:
        raise _Unsupported(
            f"{component.label} conditions require literal values"
        )
    if variable.collection == "REMOTE_ADDR" and rule.operator != "ipMatch":
        raise _Unsupported("client IP conditions require @ipMatch")

    values = list(match.values)
    notes: list[str] = []
    if component.coverage_note:
        notes.append(component.coverage_note)

    if variable.collection == "REQUEST_METHOD":
        values = _unique([value.upper() for value in values])
    elif component.encodable and not match.wildcard:
        values = _encoding_variants(values)
    elif component.encodable and match.narrowed:
        notes.append(
            "Transport encodings are enumerated at aligned depths: a "
            f"{component.label} encoded uniformly is matched, but one whose "
            "characters were encoded to differing depths is not."
        )
    elif component.encodable:
        notes.append(
            f"Only the decoded {component.label} form is matched; transport "
            "encodings are not enumerated because the match uses wildcards."
        )

    condition: dict = {
        "type": condition_type,
        "positiveMatch": not rule.negated,
    }
    if component.selector_key and variable.selector:
        condition[component.selector_key] = variable.selector
    if condition_type not in ("requestMethodMatch", "ipMatch"):
        condition["valueCase"] = case_sensitive
        condition["valueWildcard"] = match.wildcard
    condition["value"] = values
    return _CompiledCondition(
        condition=condition,
        notes=notes,
        lossy=match.lossy,
        narrowed=match.narrowed,
    )


# ---------------------------------------------------------------------------
# Bypass-driven translation requirements
# ---------------------------------------------------------------------------


def _required_condition_types(
    requirements: ProofLoopTranslationRequirements,
) -> set[str]:
    location = " ".join(
        str(value) for value in (requirements.mutation_location or {}).values()
    ).lower()
    if "header" in location:
        return {"requestHeaderValueMatch"}
    if "query" in location:
        return {"uriQueryMatch"}
    if "cookie" in location:
        return {"cookieMatch"}
    if "path" in location:
        return {"pathMatch"}
    return set(_BODY_CONDITIONS)


def _apply_requirements(
    conditions: list[dict],
    requirements: ProofLoopTranslationRequirements,
) -> list[str]:
    """Fold proven bypass payloads into the compiled conditions.

    Values inside one Akamai condition are OR-ed, so a required payload can
    only be added to an existing condition of the right component. If there is
    no such condition the compiler declines and the doer, which is
    requirement-aware, handles the request instead.
    """
    notes: list[str] = []
    payloads = [item for item in requirements.required_payloads if item]
    if payloads:
        required_types = _required_condition_types(requirements)
        targets = [
            condition
            for condition in conditions
            if condition["type"] in required_types
        ]
        if not targets:
            raise _Unsupported(
                "compiled rule has no condition for the component the bypass "
                "counterexample mutated"
            )
        target = targets[0]
        target["value"] = _unique([*target["value"], *payloads])
        notes.append(
            "Proven bypass payload forms from Bypass Validation were added to "
            "the matching condition."
        )
    if requirements.request_path and not any(
        condition["type"] == "pathMatch" for condition in conditions
    ):
        conditions.append(
            {
                "type": "pathMatch",
                "positiveMatch": True,
                "valueCase": False,
                "valueWildcard": False,
                "value": [requirements.request_path],
            }
        )
        notes.append(
            "The rule is scoped to the authoritative proven request path."
        )
    return notes


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def compile_akamai_custom_rule(
    pattern: ProvenMitigationPattern,
    *,
    translation_requirements: ProofLoopTranslationRequirements | None = None,
) -> TranslationProposal | None:
    """Compile the proven ModSecurity rule into an Akamai custom rule.

    Returns `None` when the source rule uses a construct this compiler cannot
    map with certainty, so the caller can fall back to the translation doer.
    """
    try:
        return _compile(pattern, translation_requirements)
    except _Unsupported:
        return None
    except (RecursionError, ValueError):
        return None


def _compile(
    pattern: ProvenMitigationPattern,
    requirements: ProofLoopTranslationRequirements | None,
) -> TranslationProposal | None:
    directives = _split_directives(pattern.pattern_summary)
    if not directives:
        return None
    if len(directives) > _MAX_RULES:
        raise _Unsupported("too many SecRule directives")

    rules = [_parse_secrule(directive) for directive in directives]
    chained = any(rule.chained for rule in rules[:-1])
    if len(rules) > 1 and not chained:
        raise _Unsupported(
            "independent SecRule directives do not compose into one custom rule"
        )

    conditions: list[dict] = []
    mappings: list[str] = []
    notes: list[str] = []
    lossy = False
    narrowed = False
    for rule in rules:
        match = _operator_match(rule)
        case_sensitive = not (
            match.case_insensitive or "lowercase" in rule.transformations
        )
        if len(rules) > 1 and len(rule.variables) > 1:
            raise _Unsupported(
                "a chained SecRule with alternative variables cannot be "
                "expressed under a single AND operation"
            )
        for variable in rule.variables:
            compiled = _build_condition(
                variable, rule, match, case_sensitive=case_sensitive
            )
            conditions.append(compiled.condition)
            mappings.append(
                f"{_variable_label(variable)} @{rule.operator} -> "
                f"{compiled.condition['type']}"
            )
            notes.extend(compiled.notes)
            lossy = lossy or compiled.lossy
            narrowed = narrowed or compiled.narrowed
        if rule.transformations and not set(rule.transformations) <= {
            "none",
            "lowercase",
            "urldecode",
            "urldecodeuni",
            "utf8tounicode",
            "removenulls",
            "compresswhitespace",
            "normalizepath",
            "htmlentitydecode",
        }:
            raise _Unsupported("unsupported ModSecurity transformation")

    if not conditions:
        raise _Unsupported("no conditions were produced")
    if requirements is not None:
        notes.extend(_apply_requirements(conditions, requirements))

    operation = "AND" if len(conditions) == 1 or chained else "OR"
    source_tags = _unique(
        [tag for rule in rules for tag in rule.tags if _is_safe_tag(tag)]
    )
    message = next((rule.message for rule in rules if rule.message), None)
    components = _unique([_condition_label(condition) for condition in conditions])
    rule_body = {
        "name": _rule_name(pattern, rules[0].variables[0], conditions),
        "description": (
            message
            or (
                f"Compiled from the proven ModSecurity rule for "
                f"{pattern.vulnerability_id}; matches "
                f"{', '.join(components)}."
            )
        ),
        "operation": operation,
        "conditions": conditions,
        "tag": _unique(
            [
                "JANUS",
                pattern.vulnerability_id,
                "modsec-derived",
                "virtual-patch",
                *source_tags,
            ]
        ),
    }

    label = "narrower" if lossy or narrowed else "equivalent"
    assumptions = [
        "The proven ModSecurity rule in the upstream defense-generation "
        "artifact is the authoritative source of the match semantics.",
        "Akamai evaluates the mapped condition types against the same request "
        "components ModSecurity inspected.",
        "The custom-rule action is assigned at the security-policy binding; "
        "recommended action: deny.",
    ]
    limitations = [
        "The candidate is shape-validated only and has not been executed in an "
        "Akamai tenant.",
        *_unique(notes),
    ]
    if lossy:
        limitations.append(
            "Regex constructs without a wildcard equivalent were generalized, "
            "so the candidate can match a broader set of requests than the "
            "source rule. Operator review of collateral impact is required."
        )
    if narrowed:
        limitations.append(
            "The source rule enumerated recursive encodings of individual "
            "characters. The candidate matches those encodings applied "
            "uniformly, one value per depth, rather than every combination of "
            "differing depths; a request mixing encoding depths within one "
            "value would not match."
        )
    return TranslationProposal(
        candidate_content=rule_body,
        translation_label=label,
        justification=(
            "Compiled the proven ModSecurity SecRule deterministically into "
            "Akamai custom-rule conditions: "
            + "; ".join(mappings)
            + "."
        ),
        translation_assumptions=assumptions,
        limitations=limitations,
    )


def _variable_label(variable: _Variable) -> str:
    if variable.selector:
        return f"{variable.collection}:{variable.selector}"
    return variable.collection


def _condition_label(condition: dict) -> str:
    for component in _COMPONENTS.values():
        if component.condition_type == condition["type"]:
            return component.label
    return condition["type"]


def _is_safe_tag(tag: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9 ._:/-]{1,64}", tag))


def _rule_name(
    pattern: ProvenMitigationPattern,
    variable: _Variable,
    conditions: list[dict],
) -> str:
    suffix = _slug(variable.selector or _condition_label(conditions[0]))
    return f"JANUS-{pattern.vulnerability_id}-{suffix}"


def _slug(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-")
    return cleaned or "Rule"
