package translation

// Deterministic ModSecurity -> Akamai custom WAF rule compiler.
//
// This is the default execution path for akamai-waf translation. The proven
// mitigation pattern's PatternSummary carries the authoritative
// defense-generation artifact, which is a ModSecurity SecRule. This file
// compiles that rule mechanically into the Akamai Application Security
// custom-rule JSON shape documented in docs/syntexresearch.md
// (operation + conditions[]), so a translation that code can derive is never
// delegated to a model.
//
// The compiler is deliberately conservative. Any construct whose Akamai
// equivalent is not known with certainty makes it decline (return nil), and
// engine.go falls back to the translation doer. Output is still untrusted: it
// passes the same adapter syntax gate and conflict gate as any doer proposal.
//
// Ported from src/control_translation/translation/modsec_akamai.py. The two
// implementations must produce byte-identical rule JSON.

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/ATT-CSO/control-translation/go-api/internal/contracts"
	"github.com/ATT-CSO/control-translation/go-api/internal/jsonx"
)

// A proven pattern is small; anything larger signals the source is not the
// single virtual-patch rule this path is designed for.
const (
	maxRules          = 8
	maxValues         = 32
	maxClassMembers   = 8
	maxRegexLength    = 4096
	maxArgumentLength = 4096
	maxRegexNestDepth = 8
)

var secRuleLine = regexp.MustCompile(`(?i)^\s*SecRule\b`)

// errUnsupported marks a construct with no certain Akamai equivalent.
var errUnsupported = errors.New("unsupported ModSecurity construct")

func unsupported(reason string) error { return fmt.Errorf("%w: %s", errUnsupported, reason) }

// component describes how one ModSecurity collection maps onto Akamai.
type component struct {
	conditionType string
	label         string
	selectorKey   string
	encodable     bool
	literalOnly   bool
	coverageNote  string
}

const (
	argsCoverageNote = "ModSecurity ARGS covers query-string and request-body arguments; the " +
		"Akamai candidate matches POST body arguments only. Add an equivalent " +
		"uriQueryMatch condition if the endpoint also accepts this parameter in " +
		"the query string."
	uriCoverageNote = "ModSecurity REQUEST_URI includes the query string; pathMatch inspects " +
		"the URI path only."
	anyHeaderCondition = "requestHeaderMatch"
)

var components = map[string]component{
	"ARGS":             {"argsPostMatch", "POST argument", "parameter", true, false, argsCoverageNote},
	"ARGS_POST":        {"argsPostMatch", "POST argument", "parameter", true, false, ""},
	"ARGS_GET":         {"uriQueryMatch", "query string", "", true, false, ""},
	"QUERY_STRING":     {"uriQueryMatch", "query string", "", true, false, ""},
	"REQUEST_BODY":     {"argsPostMatch", "request body", "", true, false, ""},
	"XML":              {"argsPostXMLMatch", "XML request body", "", false, false, ""},
	"REQUEST_HEADERS":  {"requestHeaderValueMatch", "request header", "header", false, false, ""},
	"REQUEST_URI":      {"pathMatch", "request path", "", true, false, uriCoverageNote},
	"REQUEST_URI_RAW":  {"pathMatch", "request path", "", true, false, uriCoverageNote},
	"REQUEST_FILENAME": {"pathMatch", "request path", "", true, false, ""},
	"REQUEST_COOKIES":  {"cookieMatch", "cookie", "name", false, false, ""},
	"REQUEST_METHOD":   {"requestMethodMatch", "request method", "", false, true, ""},
	"REMOTE_ADDR":      {"ipMatch", "client IP", "", false, true, ""},
}

// componentOrder is the label lookup order for _condition_label, matching the
// Python dict's insertion order so descriptions render identically.
var componentOrder = []string{
	"ARGS", "ARGS_POST", "ARGS_GET", "QUERY_STRING", "REQUEST_BODY", "XML",
	"REQUEST_HEADERS", "REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_FILENAME",
	"REQUEST_COOKIES", "REQUEST_METHOD", "REMOTE_ADDR",
}

// ---------------------------------------------------------------------------
// SecRule parsing
// ---------------------------------------------------------------------------

type variable struct {
	collection string
	selector   string
}

func (v variable) label() string {
	if v.selector != "" {
		return v.collection + ":" + v.selector
	}
	return v.collection
}

type secRule struct {
	variables       []variable
	negated         bool
	operator        string
	argument        string
	transformations []string
	message         string
	tags            []string
	chained         bool
}

// splitDirectives joins ModSecurity line continuations and returns SecRules.
func splitDirectives(text string) []string {
	var joined []string
	var buffer strings.Builder
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(strings.TrimSuffix(raw, "\r"), " \t")
		if strings.HasSuffix(line, `\`) {
			buffer.WriteString(strings.TrimRight(strings.TrimSuffix(line, `\`), " \t"))
			buffer.WriteString(" ")
			continue
		}
		buffer.WriteString(line)
		if strings.TrimSpace(buffer.String()) != "" {
			joined = append(joined, strings.TrimSpace(buffer.String()))
		}
		buffer.Reset()
	}
	if strings.TrimSpace(buffer.String()) != "" {
		joined = append(joined, strings.TrimSpace(buffer.String()))
	}
	directives := make([]string, 0, len(joined))
	for _, line := range joined {
		if secRuleLine.MatchString(line) {
			directives = append(directives, line)
		}
	}
	return directives
}

// tokenize splits a SecRule directive into its quoted/unquoted tokens.
func tokenize(directive string) ([]string, error) {
	body := []rune(strings.TrimSpace(directive)[len("SecRule"):])
	var tokens []string
	index, length := 0, len(body)
	for index < length {
		for index < length && unicode.IsSpace(body[index]) {
			index++
		}
		if index >= length {
			break
		}
		if body[index] == '"' {
			index++
			var chunk strings.Builder
			for index < length && body[index] != '"' {
				// ModSecurity only needs \" and \\ unescaped here; every other
				// backslash belongs to the regex itself.
				if body[index] == '\\' && index+1 < length &&
					(body[index+1] == '"' || body[index+1] == '\\') {
					chunk.WriteRune(body[index+1])
					index += 2
					continue
				}
				chunk.WriteRune(body[index])
				index++
			}
			if index >= length {
				return nil, unsupported("unterminated quoted token")
			}
			index++
			tokens = append(tokens, chunk.String())
			continue
		}
		start := index
		for index < length && !unicode.IsSpace(body[index]) {
			index++
		}
		tokens = append(tokens, string(body[start:index]))
	}
	return tokens, nil
}

func splitActions(actions string) []string {
	var parts []string
	var current strings.Builder
	var quote rune
	for _, char := range actions {
		if quote != 0 {
			if char == quote {
				quote = 0
			} else {
				current.WriteRune(char)
			}
			continue
		}
		switch char {
		case '\'', '"':
			quote = char
		case ',':
			if trimmed := strings.TrimSpace(current.String()); trimmed != "" {
				parts = append(parts, trimmed)
			}
			current.Reset()
		default:
			current.WriteRune(char)
		}
	}
	if trimmed := strings.TrimSpace(current.String()); trimmed != "" {
		parts = append(parts, trimmed)
	}
	return parts
}

func parseVariables(token string) ([]variable, error) {
	var variables []variable
	for _, raw := range strings.Split(token, "|") {
		item := strings.TrimSpace(raw)
		if item == "" {
			return nil, unsupported("empty variable")
		}
		if strings.HasPrefix(item, "!") {
			return nil, unsupported("variable exclusions are not expressible")
		}
		collection, selector, _ := strings.Cut(item, ":")
		selector = strings.Trim(strings.TrimSpace(selector), `'"`)
		if strings.HasPrefix(selector, "/") || strings.Contains(selector, "*") {
			return nil, unsupported("regex variable selectors are not expressible")
		}
		variables = append(variables, variable{
			collection: strings.ToUpper(strings.TrimSpace(collection)),
			selector:   selector,
		})
	}
	if len(variables) == 0 {
		return nil, unsupported("no variables")
	}
	return variables, nil
}

func parseSecRule(directive string) (secRule, error) {
	tokens, err := tokenize(directive)
	if err != nil {
		return secRule{}, err
	}
	if len(tokens) < 2 {
		return secRule{}, unsupported("SecRule needs a variable and an operator")
	}
	variables, err := parseVariables(tokens[0])
	if err != nil {
		return secRule{}, err
	}

	operatorToken := strings.TrimSpace(tokens[1])
	negated := strings.HasPrefix(operatorToken, "!")
	if negated {
		operatorToken = strings.TrimLeft(operatorToken[1:], " \t")
	}
	if !strings.HasPrefix(operatorToken, "@") {
		// An implicit operator means the token is raw regex. Refusing it keeps
		// prose and malformed producer output out of this path.
		return secRule{}, unsupported("SecRule operator must be explicit (@rx, @contains, ...)")
	}
	operator, argument, _ := strings.Cut(operatorToken[1:], " ")
	operator = strings.TrimSpace(operator)
	argument = strings.TrimSpace(argument)
	if len(argument) > maxArgumentLength {
		return secRule{}, unsupported("operator argument is too large")
	}

	rule := secRule{
		variables: variables,
		negated:   negated,
		operator:  operator,
		argument:  argument,
	}
	var actions string
	if len(tokens) > 2 {
		actions = tokens[2]
	}
	for _, action := range splitActions(actions) {
		name, value, _ := strings.Cut(action, ":")
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		switch name {
		case "t":
			rule.transformations = append(rule.transformations, strings.ToLower(value))
		case "msg":
			if value != "" {
				rule.message = value
			}
		case "tag":
			if value != "" {
				rule.tags = append(rule.tags, value)
			}
		case "chain":
			rule.chained = true
		}
	}
	return rule, nil
}

// ---------------------------------------------------------------------------
// Regex -> Akamai wildcard values
// ---------------------------------------------------------------------------

type partKind int

const (
	partLit partKind = iota
	partAny
	partOne
	// partLadder is one literal written at several recursive URL-encoding
	// depths, e.g. "[" then "%5B" then "%255B". It renders as exactly one of
	// them, chosen by the depth being emitted.
	partLadder
)

type part struct {
	kind   partKind
	char   rune
	ladder []string
}

var (
	anyPart = part{kind: partAny}
	onePart = part{kind: partOne}
)

var escapeLiterals = map[rune]rune{'n': '\n', 'r': '\r', 't': '\t', 'f': '\f', 'v': '\v'}

func isClassShorthand(char rune) bool { return strings.ContainsRune("sSdDwW", char) }

type regexResult struct {
	values          []string
	wildcard        bool
	caseInsensitive bool
	// lossy marks a generalization that can match MORE than the source.
	lossy bool
	// narrowed marks encoding-ladder alignment, which matches LESS: only
	// uniformly encoded bodies, not every mixed-depth combination.
	narrowed bool
}

// regexTranslator expands a bounded regex subset into Akamai wildcard values.
// Akamai string conditions match literals with `*` (any run) and `?` (one
// character) when valueWildcard is set, so only regex constructs with a
// faithful wildcard image are accepted; everything else declines.
type regexTranslator struct {
	source          []rune
	index           int
	lossy           bool
	narrowed        bool
	caseInsensitive bool
}

var inlineFlags = regexp.MustCompile(`^\(\?([a-zA-Z]+)\)`)

func translateRegex(source string) (regexResult, error) {
	if len(source) > maxRegexLength {
		return regexResult{}, unsupported("regex is too large")
	}
	translator := &regexTranslator{source: []rune(source)}
	if err := translator.readInlineFlags(); err != nil {
		return regexResult{}, err
	}

	anchoredStart := false
	if translator.index < len(translator.source) && translator.source[translator.index] == '^' {
		anchoredStart = true
		translator.index++
	}
	body := translator.source[translator.index:]
	anchoredEnd := false
	if len(body) > 0 && body[len(body)-1] == '$' &&
		!(len(body) > 1 && body[len(body)-2] == '\\') {
		anchoredEnd = true
		body = body[:len(body)-1]
	}
	translator.source = body
	translator.index = 0

	alternatives, err := translator.parseAlternation(0)
	if err != nil {
		return regexResult{}, err
	}
	if translator.index != len(translator.source) {
		return regexResult{}, unsupported("unbalanced regex group")
	}

	depths := 1
	if common, ok := ladderDepth(alternatives); ok {
		depths = common
	} else if hasLadder(alternatives) {
		return regexResult{}, unsupported("encoding ladders of differing depths cannot be aligned")
	}

	wildcard := !anchoredStart || !anchoredEnd
	values := make([]string, 0, len(alternatives)*depths)
	// One value per encoding depth, with every ladder rendered at that same
	// depth: the combinations a uniformly encoded body actually produces.
	for depth := 0; depth < depths; depth++ {
		for _, parts := range alternatives {
			rendered, usedWildcard := render(parts, depth)
			wildcard = wildcard || usedWildcard
			if !anchoredStart {
				rendered = "*" + rendered
			}
			if !anchoredEnd {
				rendered += "*"
			}
			values = append(values, rendered)
		}
	}
	if len(values) > maxValues {
		return regexResult{}, unsupported("regex expands to too many values")
	}
	values = uniqueStrings(values)
	if len(values) == 0 {
		return regexResult{}, unsupported("regex produced an empty match value")
	}
	for _, value := range values {
		if value == "" {
			return regexResult{}, unsupported("regex produced an empty match value")
		}
	}
	if wildcard {
		for _, parts := range alternatives {
			if hasLiteralWildcard(parts) {
				return regexResult{}, unsupported("literal '*' or '?' cannot coexist with wildcards")
			}
		}
	}
	return regexResult{
		values:          values,
		wildcard:        wildcard,
		caseInsensitive: translator.caseInsensitive,
		lossy:           translator.lossy,
		narrowed:        translator.narrowed,
	}, nil
}

func (t *regexTranslator) readInlineFlags() error {
	match := inlineFlags.FindStringSubmatch(string(t.source))
	if match == nil {
		return nil
	}
	for _, flag := range match[1] {
		if flag != 'i' && flag != 's' {
			return unsupported("unsupported inline regex flags: " + match[1])
		}
	}
	t.caseInsensitive = strings.ContainsRune(match[1], 'i')
	t.index = len([]rune(match[0]))
	return nil
}

func (t *regexTranslator) parseAlternation(depth int) ([][]part, error) {
	if depth > maxRegexNestDepth {
		return nil, unsupported("regex nesting is too deep")
	}
	alternatives, err := t.parseConcat(depth)
	if err != nil {
		return nil, err
	}
	for t.index < len(t.source) && t.source[t.index] == '|' {
		t.index++
		more, err := t.parseConcat(depth)
		if err != nil {
			return nil, err
		}
		alternatives = append(alternatives, more...)
		if len(alternatives) > maxValues {
			return nil, unsupported("regex expands to too many values")
		}
	}
	return alternatives, nil
}

func (t *regexTranslator) parseConcat(depth int) ([][]part, error) {
	results := [][]part{{}}
	for t.index < len(t.source) && t.source[t.index] != '|' && t.source[t.index] != ')' {
		term, err := t.parseTerm(depth)
		if err != nil {
			return nil, err
		}
		combined := make([][]part, 0, len(results)*len(term))
		for _, prefix := range results {
			for _, suffix := range term {
				merged := make([]part, 0, len(prefix)+len(suffix))
				merged = append(merged, prefix...)
				merged = append(merged, suffix...)
				combined = append(combined, merged)
			}
		}
		if len(combined) > maxValues {
			return nil, unsupported("regex expands to too many values")
		}
		results = combined
	}
	return results, nil
}

func (t *regexTranslator) parseTerm(depth int) ([][]part, error) {
	alternatives, singleChar, err := t.parseAtom(depth)
	if err != nil {
		return nil, err
	}
	if t.index >= len(t.source) || !strings.ContainsRune("*+?", t.source[t.index]) {
		return alternatives, nil
	}
	quantifier := t.source[t.index]
	t.index++
	if t.index < len(t.source) && (t.source[t.index] == '?' || t.source[t.index] == '+') {
		t.index++ // lazy / possessive marker
	}
	if !singleChar {
		return nil, unsupported("quantified groups are not expressible")
	}
	var expanded [][]part
	if quantifier == '+' {
		// Keep one concrete occurrence, then allow the repetition.
		for _, parts := range alternatives {
			expanded = append(expanded, append(append([]part{}, parts...), anyPart))
		}
	} else {
		expanded = [][]part{{anyPart}}
	}
	// Quantifying '.' keeps full fidelity; quantifying a literal or an
	// enumerated class widens the match.
	if !isSingleOnePart(alternatives) {
		t.lossy = true
	}
	return expanded, nil
}

// isSingleOnePart reports whether the atom is a bare single-character
// wildcard, i.e. `.`, for which quantifying loses nothing.
func isSingleOnePart(alternatives [][]part) bool {
	return len(alternatives) == 1 && len(alternatives[0]) == 1 &&
		alternatives[0][0].kind == partOne
}

func (t *regexTranslator) parseAtom(depth int) ([][]part, bool, error) {
	char := t.source[t.index]
	switch {
	case char == '(':
		rest := string(t.source[t.index:])
		if strings.HasPrefix(rest, "(?") && !strings.HasPrefix(rest, "(?:") {
			return nil, false, unsupported("lookarounds and inline groups are not expressible")
		}
		if strings.HasPrefix(rest, "(?:") {
			t.index += 3
		} else {
			t.index++
		}
		alternatives, err := t.parseAlternation(depth + 1)
		if err != nil {
			return nil, false, err
		}
		if t.index >= len(t.source) || t.source[t.index] != ')' {
			return nil, false, unsupported("unbalanced regex group")
		}
		t.index++
		if ladder := asEncodingLadder(alternatives); ladder != nil {
			t.narrowed = true
			return [][]part{{{kind: partLadder, ladder: ladder}}}, false, nil
		}
		single := true
		for _, parts := range alternatives {
			if len(parts) != 1 {
				single = false
				break
			}
		}
		return alternatives, single, nil
	case char == '[':
		alternatives, err := t.parseClass()
		return alternatives, true, err
	case char == '\\':
		return t.parseEscape()
	case char == '.':
		t.index++
		return [][]part{{onePart}}, true, nil
	case char == '^' || char == '$':
		return nil, false, unsupported("anchors are only supported at the pattern edges")
	case char == '{' || char == '}':
		return nil, false, unsupported("counted repetition is not expressible")
	default:
		t.index++
		return [][]part{{{kind: partLit, char: char}}}, true, nil
	}
}

func (t *regexTranslator) parseClass() ([][]part, error) {
	end := -1
	for index := t.index + 1; index < len(t.source); index++ {
		if t.source[index] == ']' {
			end = index
			break
		}
	}
	if end == -1 {
		return nil, unsupported("unterminated character class")
	}
	body := string(t.source[t.index+1 : end])
	t.index = end + 1
	if body == "" || strings.HasPrefix(body, "^") {
		t.lossy = true
		return [][]part{{onePart}}, nil
	}
	members := enumerateClass(body)
	if members == nil || len(members) > maxClassMembers {
		t.lossy = true
		return [][]part{{onePart}}, nil
	}
	alternatives := make([][]part, 0, len(members))
	for _, member := range members {
		alternatives = append(alternatives, []part{{kind: partLit, char: member}})
	}
	return alternatives, nil
}

func (t *regexTranslator) parseEscape() ([][]part, bool, error) {
	if t.index+1 >= len(t.source) {
		return nil, false, unsupported("dangling escape")
	}
	char := t.source[t.index+1]
	t.index += 2
	switch {
	case isClassShorthand(char):
		t.lossy = true
		return [][]part{{onePart}}, true, nil
	case char == 'b' || char == 'B':
		// Word boundaries have no wildcard image; dropping them widens the
		// match, which the caller records as a limitation.
		t.lossy = true
		return [][]part{{}}, false, nil
	case escapeLiterals[char] != 0:
		return [][]part{{{kind: partLit, char: escapeLiterals[char]}}}, true, nil
	case char == 'x':
		if t.index+2 > len(t.source) {
			return nil, false, unsupported("unsupported hexadecimal escape")
		}
		digits := string(t.source[t.index : t.index+2])
		code, err := strconv.ParseInt(digits, 16, 32)
		if err != nil {
			return nil, false, unsupported("unsupported hexadecimal escape")
		}
		t.index += 2
		return [][]part{{{kind: partLit, char: rune(code)}}}, true, nil
	case unicode.IsLetter(char) || unicode.IsDigit(char):
		return nil, false, unsupported("unsupported regex escape: \\" + string(char))
	default:
		return [][]part{{{kind: partLit, char: char}}}, true, nil
	}
}

func enumerateClass(body string) []rune {
	runes := []rune(body)
	var members []rune
	index := 0
	for index < len(runes) {
		char := runes[index]
		if char == '\\' {
			if index+1 >= len(runes) {
				return nil
			}
			following := runes[index+1]
			if isClassShorthand(following) || unicode.IsLetter(following) || unicode.IsDigit(following) {
				literal, ok := escapeLiterals[following]
				if !ok {
					return nil
				}
				members = append(members, literal)
			} else {
				members = append(members, following)
			}
			index += 2
			continue
		}
		if index+2 < len(runes) && runes[index+1] == '-' {
			start, stop := char, runes[index+2]
			if stop < start || int(stop-start) >= maxClassMembers {
				return nil
			}
			for code := start; code <= stop; code++ {
				members = append(members, code)
			}
			index += 3
			continue
		}
		members = append(members, char)
		index++
	}
	if len(members) == 0 {
		return nil
	}
	return uniqueRunes(members)
}

func render(parts []part, depth int) (string, bool) {
	var builder strings.Builder
	usedWildcard := false
	lastWasAny := false
	for _, item := range parts {
		switch item.kind {
		case partLadder:
			builder.WriteString(item.ladder[depth])
		case partAny:
			usedWildcard = true
			if lastWasAny {
				continue
			}
			builder.WriteByte('*')
			lastWasAny = true
			continue
		case partOne:
			usedWildcard = true
			builder.WriteByte('?')
		default:
			builder.WriteRune(item.char)
		}
		lastWasAny = false
	}
	return builder.String(), usedWildcard
}

// asEncodingLadder reports whether every branch of a group is the previous
// branch URL-encoded once more -- the shape defense generation emits when it
// enumerates recursive encodings of one character, e.g.
// (?:\[|%5B|%255B|%25255B). It returns the branches in depth order, or nil.
//
// Expanding such groups positionally is what makes a rule with several of them
// explode combinatorially, because it enumerates bodies whose characters were
// each encoded a different number of times. Real traffic encodes a body at one
// depth, so the caller emits one value per depth instead.
func asEncodingLadder(alternatives [][]part) []string {
	if len(alternatives) < 2 {
		return nil
	}
	branches := make([]string, 0, len(alternatives))
	for _, parts := range alternatives {
		var builder strings.Builder
		for _, item := range parts {
			if item.kind != partLit {
				return nil
			}
			builder.WriteRune(item.char)
		}
		if builder.Len() == 0 {
			return nil
		}
		branches = append(branches, builder.String())
	}
	for index := 1; index < len(branches); index++ {
		if branches[index] != quoteAll(branches[index-1]) {
			return nil
		}
	}
	return branches
}

// ladderDepth returns the common depth of every ladder in the alternatives, or
// (0, false) when there is none or they disagree. Ladders of differing lengths
// have no single depth to align on, so those fall back to plain expansion.
func ladderDepth(alternatives [][]part) (int, bool) {
	depth := 0
	for _, parts := range alternatives {
		for _, item := range parts {
			if item.kind != partLadder {
				continue
			}
			if depth == 0 {
				depth = len(item.ladder)
				continue
			}
			if depth != len(item.ladder) {
				return 0, false
			}
		}
	}
	return depth, depth > 0
}

func hasLadder(alternatives [][]part) bool {
	for _, parts := range alternatives {
		for _, item := range parts {
			if item.kind == partLadder {
				return true
			}
		}
	}
	return false
}

func hasLiteralWildcard(parts []part) bool {
	for _, item := range parts {
		if item.kind == partLit && (item.char == '*' || item.char == '?') {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func uniqueRunes(values []rune) []rune {
	seen := make(map[rune]bool, len(values))
	out := make([]rune, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// ---------------------------------------------------------------------------
// Operator -> match values
// ---------------------------------------------------------------------------

type match struct {
	values          []string
	wildcard        bool
	caseInsensitive bool
	lossy           bool
	narrowed        bool
}

func operatorMatch(rule secRule) (match, error) {
	argument := rule.argument
	switch rule.operator {
	case "rx":
		result, err := translateRegex(argument)
		if err != nil {
			return match{}, err
		}
		return match{
			values:          result.values,
			wildcard:        result.wildcard,
			caseInsensitive: result.caseInsensitive,
			lossy:           result.lossy,
			narrowed:        result.narrowed,
		}, nil
	case "contains":
		if argument == "" {
			return match{}, unsupported("empty operator argument")
		}
		return match{values: []string{"*" + argument + "*"}, wildcard: true}, nil
	case "beginsWith":
		if argument == "" {
			return match{}, unsupported("empty operator argument")
		}
		return match{values: []string{argument + "*"}, wildcard: true}, nil
	case "endsWith":
		if argument == "" {
			return match{}, unsupported("empty operator argument")
		}
		return match{values: []string{"*" + argument}, wildcard: true}, nil
	case "streq", "eq":
		if argument == "" {
			return match{}, unsupported("empty operator argument")
		}
		return match{values: []string{argument}}, nil
	case "within":
		members := uniqueStrings(strings.Fields(argument))
		if len(members) == 0 {
			return match{}, unsupported("empty @within list")
		}
		return match{values: members}, nil
	case "pm":
		members := uniqueStrings(strings.Fields(argument))
		if len(members) == 0 {
			return match{}, unsupported("empty @pm list")
		}
		if len(members) > maxValues {
			return match{}, unsupported("@pm list is too large")
		}
		values := make([]string, 0, len(members))
		for _, item := range members {
			values = append(values, "*"+item+"*")
		}
		return match{values: values, wildcard: true, caseInsensitive: true}, nil
	case "ipMatch":
		members := uniqueStrings(strings.FieldsFunc(argument, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		}))
		if len(members) == 0 {
			return match{}, unsupported("empty @ipMatch list")
		}
		return match{values: members}, nil
	default:
		return match{}, unsupported("unsupported ModSecurity operator: @" + rule.operator)
	}
}

// encodingVariants adds the transport encodings an edge WAF may observe.
func encodingVariants(values []string) []string {
	variants := make([]string, 0, len(values)*4)
	for _, value := range values {
		encodedOnce := quoteAll(value)
		variants = append(variants,
			value,
			encodedOnce,
			quotePlusAll(value),
			quoteAll(encodedOnce),
		)
	}
	return uniqueStrings(variants)
}

// quoteAll matches Python's urllib.parse.quote(value, safe="").
func quoteAll(value string) string {
	var builder strings.Builder
	for _, b := range []byte(value) {
		if isURLUnreserved(b) {
			builder.WriteByte(b)
			continue
		}
		builder.WriteString(fmt.Sprintf("%%%02X", b))
	}
	return builder.String()
}

// quotePlusAll matches Python's urllib.parse.quote_plus(value, safe="").
func quotePlusAll(value string) string {
	return strings.ReplaceAll(quoteAll(value), "%20", "+")
}

func isURLUnreserved(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	case b == '_' || b == '.' || b == '-' || b == '~':
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Condition assembly
// ---------------------------------------------------------------------------

type compiledCondition struct {
	condition jsonx.Obj
	notes     []string
	lossy     bool
	narrowed  bool
}

func buildCondition(v variable, rule secRule, m match, caseSensitive bool) (compiledCondition, error) {
	comp, known := components[v.collection]
	if !known {
		return compiledCondition{}, unsupported("unsupported ModSecurity collection: " + v.collection)
	}
	conditionType := comp.conditionType
	if comp.selectorKey == "header" && v.selector == "" {
		conditionType = anyHeaderCondition
	}
	if comp.literalOnly && m.wildcard {
		return compiledCondition{}, unsupported(comp.label + " conditions require literal values")
	}
	if v.collection == "REMOTE_ADDR" && rule.operator != "ipMatch" {
		return compiledCondition{}, unsupported("client IP conditions require @ipMatch")
	}

	values := append([]string{}, m.values...)
	var notes []string
	if comp.coverageNote != "" {
		notes = append(notes, comp.coverageNote)
	}
	switch {
	case v.collection == "REQUEST_METHOD":
		upper := make([]string, 0, len(values))
		for _, value := range values {
			upper = append(upper, strings.ToUpper(value))
		}
		values = uniqueStrings(upper)
	case comp.encodable && !m.wildcard:
		values = encodingVariants(values)
	case comp.encodable && m.narrowed:
		notes = append(notes, "Transport encodings are enumerated at aligned depths: a "+
			comp.label+" encoded uniformly is matched, but one whose characters were "+
			"encoded to differing depths is not.")
	case comp.encodable:
		notes = append(notes, "Only the decoded "+comp.label+" form is matched; transport "+
			"encodings are not enumerated because the match uses wildcards.")
	}

	condition := jsonx.Obj{}.
		Set("type", conditionType).
		Set("positiveMatch", !rule.negated)
	if comp.selectorKey != "" && v.selector != "" {
		condition = condition.Set(comp.selectorKey, v.selector)
	}
	if conditionType != "requestMethodMatch" && conditionType != "ipMatch" {
		condition = condition.Set("valueCase", caseSensitive).Set("valueWildcard", m.wildcard)
	}
	condition = condition.Set("value", values)
	return compiledCondition{
		condition: condition, notes: notes, lossy: m.lossy, narrowed: m.narrowed,
	}, nil
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

var allowedTransformations = map[string]bool{
	"none": true, "lowercase": true, "urldecode": true, "urldecodeuni": true,
	"utf8tounicode": true, "removenulls": true, "compresswhitespace": true,
	"normalizepath": true, "htmlentitydecode": true,
}

var safeTag = regexp.MustCompile(`^[A-Za-z0-9 ._:/-]{1,64}$`)

// CompileAkamaiCustomRule compiles the proven ModSecurity rule into an Akamai
// custom rule. It returns nil when the source uses a construct the compiler
// cannot map with certainty, so the caller can fall back to the doer.
func CompileAkamaiCustomRule(pattern contracts.ProvenMitigationPattern) *Proposal {
	proposal, err := compileAkamai(pattern)
	if err != nil {
		return nil
	}
	return proposal
}

func compileAkamai(pattern contracts.ProvenMitigationPattern) (*Proposal, error) {
	directives := splitDirectives(pattern.PatternSummary)
	if len(directives) == 0 {
		return nil, unsupported("no SecRule directives")
	}
	if len(directives) > maxRules {
		return nil, unsupported("too many SecRule directives")
	}

	rules := make([]secRule, 0, len(directives))
	for _, directive := range directives {
		rule, err := parseSecRule(directive)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	chained := false
	for _, rule := range rules[:len(rules)-1] {
		if rule.chained {
			chained = true
		}
	}
	if len(rules) > 1 && !chained {
		return nil, unsupported("independent SecRule directives do not compose into one custom rule")
	}

	var conditions []jsonx.Obj
	var mappings, notes []string
	lossy, narrowed := false, false
	for _, rule := range rules {
		m, err := operatorMatch(rule)
		if err != nil {
			return nil, err
		}
		caseSensitive := !(m.caseInsensitive || containsString(rule.transformations, "lowercase"))
		if len(rules) > 1 && len(rule.variables) > 1 {
			return nil, unsupported("a chained SecRule with alternative variables cannot be " +
				"expressed under a single AND operation")
		}
		for _, v := range rule.variables {
			compiled, err := buildCondition(v, rule, m, caseSensitive)
			if err != nil {
				return nil, err
			}
			conditions = append(conditions, compiled.condition)
			mappings = append(mappings, v.label()+" @"+rule.operator+" -> "+compiled.condition.MustString("type"))
			notes = append(notes, compiled.notes...)
			lossy = lossy || compiled.lossy
			narrowed = narrowed || compiled.narrowed
		}
		for _, transformation := range rule.transformations {
			if !allowedTransformations[transformation] {
				return nil, unsupported("unsupported ModSecurity transformation")
			}
		}
	}

	if len(conditions) == 0 {
		return nil, unsupported("no conditions were produced")
	}

	operation := "OR"
	if len(conditions) == 1 || chained {
		operation = "AND"
	}
	var sourceTags []string
	for _, rule := range rules {
		for _, tag := range rule.tags {
			if safeTag.MatchString(tag) {
				sourceTags = append(sourceTags, tag)
			}
		}
	}
	sourceTags = uniqueStrings(sourceTags)
	message := ""
	for _, rule := range rules {
		if rule.message != "" {
			message = rule.message
			break
		}
	}
	componentLabels := make([]string, 0, len(conditions))
	for _, condition := range conditions {
		componentLabels = append(componentLabels, conditionLabel(condition.MustString("type")))
	}
	componentLabels = uniqueStrings(componentLabels)

	description := message
	if description == "" {
		description = "Compiled from the proven ModSecurity rule for " + pattern.VulnerabilityID +
			"; matches " + strings.Join(componentLabels, ", ") + "."
	}
	conditionValues := make([]any, 0, len(conditions))
	for _, condition := range conditions {
		conditionValues = append(conditionValues, condition)
	}
	tags := uniqueStrings(append([]string{
		"JANUS", pattern.VulnerabilityID, "modsec-derived", "virtual-patch",
	}, sourceTags...))

	ruleBody := jsonx.Obj{}.
		Set("name", ruleName(pattern, rules[0].variables[0], conditions)).
		Set("description", description).
		Set("operation", operation).
		Set("conditions", conditionValues).
		Set("tag", tags)

	label := "equivalent"
	if lossy || narrowed {
		label = "narrower"
	}
	limitations := append([]string{
		"The candidate is shape-validated only and has not been executed in an Akamai tenant.",
	}, uniqueStrings(notes)...)
	if lossy {
		limitations = append(limitations,
			"Regex constructs without a wildcard equivalent were generalized, so the "+
				"candidate can match a broader set of requests than the source rule. "+
				"Operator review of collateral impact is required.")
	}
	if narrowed {
		limitations = append(limitations,
			"The source rule enumerated recursive encodings of individual characters. "+
				"The candidate matches those encodings applied uniformly, one value per "+
				"depth, rather than every combination of differing depths; a request "+
				"mixing encoding depths within one value would not match.")
	}
	return &Proposal{
		CandidateContent: ruleBody,
		TranslationLabel: label,
		Justification: "Compiled the proven ModSecurity SecRule deterministically into " +
			"Akamai custom-rule conditions: " + strings.Join(mappings, "; ") + ".",
		TranslationAssumptions: []string{
			"The proven ModSecurity rule in the upstream defense-generation " +
				"artifact is the authoritative source of the match semantics.",
			"Akamai evaluates the mapped condition types against the same request " +
				"components ModSecurity inspected.",
			"The custom-rule action is assigned at the security-policy binding; " +
				"recommended action: deny.",
		},
		Limitations: limitations,
	}, nil
}

func conditionLabel(conditionType string) string {
	for _, key := range componentOrder {
		if components[key].conditionType == conditionType {
			return components[key].label
		}
	}
	return conditionType
}

func ruleName(pattern contracts.ProvenMitigationPattern, v variable, conditions []jsonx.Obj) string {
	suffix := v.selector
	if suffix == "" {
		suffix = conditionLabel(conditions[0].MustString("type"))
	}
	return "JANUS-" + pattern.VulnerabilityID + "-" + slug(suffix)
}

var nonAlphanumeric = regexp.MustCompile(`[^A-Za-z0-9]+`)

func slug(text string) string {
	cleaned := strings.Trim(nonAlphanumeric.ReplaceAllString(text, "-"), "-")
	if cleaned == "" {
		return "Rule"
	}
	return cleaned
}

func containsString(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}
