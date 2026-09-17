package upstream

// Producer results are signed by the Go services that emit them: content_sha256
// covers the bytes encoding/json produced for the result struct. Databricks
// stores those rows as VARIANT, which normalizes the JSON -- key order and
// escaping both change -- so the bytes read back are not the bytes signed.
//
// Reconstructing them is the only way to authenticate a row. This mirrors
// src/control_translation/upstream_databricks.py, which does the same in
// Python: walk a schema describing the producer's struct, emit fields in
// declaration order, apply omitempty, and escape the way encoding/json does by
// default.
//
// A schema table is used rather than Go structs on purpose. A struct
// round-trip emits a zero value for every field the stored row omitted, which
// changes the bytes; the table skips absent fields exactly as the producer's
// encoder did.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// goField is one field of a producer struct: its JSON name, the schema of its
// nested value when it has one, and which omitempty rule applies.
type goField struct {
	name      string
	schema    goSchema
	omitEmpty string // "", "pointer", "raw", "string", "slice", "number", "time"
}

type goSchema []goField

func field(name string, nested goSchema, omitEmpty string) goField {
	return goField{name: name, schema: nested, omitEmpty: omitEmpty}
}

var resultRefSchema = goSchema{
	field("system", nil, ""),
	field("catalog", nil, "string"),
	field("schema", nil, "string"),
	field("table", nil, ""),
	field("key", nil, ""),
}

var defenseOutcomeReasonSchema = goSchema{
	field("code", nil, ""),
	field("detail", nil, ""),
	field("unresolved_payload", nil, "string"),
	field("encoding_kind", nil, "string"),
	field("uncovered_required_form", nil, "string"),
	field("rejection_reason", nil, "string"),
	field("repeated_functional_fingerprint", nil, "string"),
}

var defenseCollateralPriorSchema = goSchema{
	field("verdict", nil, ""),
	field("confidence", nil, ""),
	field("basis", nil, ""),
	field("gaps", nil, ""),
	field("measured", nil, ""),
}

var defenseCandidateSchema = goSchema{
	field("candidate_id", nil, ""),
	field("selected_control_class", nil, ""),
	field("candidate_kind", nil, ""),
	field("mitigation_intent", nil, ""),
	field("discriminator", nil, ""),
	field("expected_block_behavior", nil, ""),
	field("expected_allow_behavior", nil, ""),
	field("artifact_type", nil, ""),
	field("artifact_content", nil, ""),
	field("artifact_hash", nil, ""),
	field("collateral_impact_prior", defenseCollateralPriorSchema, ""),
	field("assumptions", nil, ""),
	field("limitations", nil, ""),
	field("evidence_refs", nil, ""),
}

var defenseProofHandoffSchema = goSchema{
	field("capability", nil, ""),
	field("contract_id", nil, ""),
	field("substrate", nil, ""),
	field("candidate_ref", resultRefSchema, ""),
	field("evidence_refs", nil, "slice"),
}

var defenseAttemptSchema = goSchema{
	field("candidate_id", nil, ""),
	field("outcome", nil, ""),
	field("feedback_refs", nil, ""),
	field("do_not_repeat_constraints", nil, ""),
}

var defenseUpstreamRefSchema = goSchema{
	field("capability", nil, ""),
	field("contract_id", nil, ""),
	field("request_id", nil, "string"),
	field("correlation_id", nil, "string"),
	field("run_id", nil, "string"),
	field("result_id", nil, ""),
	field("terminal_state", nil, "string"),
	field("status", nil, "string"),
	field("result_ref", resultRefSchema, ""),
	field("evidence_refs", nil, "slice"),
	field("content_sha256", nil, "string"),
	field("size_bytes", nil, "number"),
	field("created_at", nil, "time"),
}

var defenseResultSchema = goSchema{
	field("capability", nil, ""),
	field("contract_id", nil, ""),
	field("request_id", nil, ""),
	field("correlation_id", nil, ""),
	field("run_id", nil, ""),
	field("result_id", nil, ""),
	field("status", nil, ""),
	field("terminal_state", nil, ""),
	field("result_ref", resultRefSchema, "pointer"),
	field("evidence_refs", nil, ""),
	field("outcome_reason", defenseOutcomeReasonSchema, ""),
	field("primary_candidate", defenseCandidateSchema, "pointer"),
	field("candidate_bundle", nil, "raw"),
	field("candidate_artifact_contents", nil, "raw"),
	field("proof_handoffs", defenseProofHandoffSchema, "slice"),
	field("attempt_history", defenseAttemptSchema, ""),
	field("prose_summary", nil, ""),
	field("request_digest", nil, ""),
	field("upstream_result_refs", defenseUpstreamRefSchema, ""),
	field("content_sha256", nil, "string"),
	field("size_bytes", nil, "number"),
	field("created_at", nil, ""),
}

var mitigationLocatorSchema = goSchema{
	field("capability", nil, ""),
	field("contract_id", nil, ""),
	field("request_id", nil, ""),
	field("correlation_id", nil, ""),
	field("run_id", nil, ""),
	field("result_id", nil, ""),
	field("status", nil, ""),
	field("terminal_state", nil, ""),
	field("result_ref", resultRefSchema, ""),
	field("content_sha256", nil, ""),
	field("size_bytes", nil, ""),
	field("created_at", nil, ""),
}

var mitigationProvenanceSchema = goSchema{
	field("route_policy", nil, ""),
	field("defense_result", mitigationLocatorSchema, ""),
	field("check_result", mitigationLocatorSchema, ""),
	field("selected_test_basis_id", nil, ""),
	field("verification", nil, ""),
}

var mitigationExpectedSchema = goSchema{
	field("classification", nil, ""),
	field("blocked", nil, ""),
	field("status_code", nil, ""),
}

var mitigationActualSchema = goSchema{
	field("blocked", nil, ""),
	field("status_code", nil, ""),
	field("reached_app", nil, ""),
	field("matched_rule_id", nil, "string"),
	field("detail", nil, ""),
}

var mitigationSubstrateSchema = goSchema{
	field("image", nil, ""),
	field("runner", nil, "string"),
	field("container_id", nil, "string"),
	field("host_port", nil, "number"),
	field("fqdn", nil, "string"),
	field("ready", nil, ""),
}

var mitigationCandidateSchema = goSchema{
	field("kind", nil, ""),
	field("engine", nil, ""),
	field("rule_id", nil, ""),
	field("rule", nil, ""),
	field("action", nil, ""),
}

var mitigationRequestSchema = goSchema{
	field("method", nil, ""),
	field("path", nil, ""),
	field("headers", nil, ""),
	field("body", nil, ""),
}

var mitigationTestBasisSchema = goSchema{
	field("kind", nil, ""),
	field("proof_basis", nil, ""),
	field("request", mitigationRequestSchema, ""),
	field("expected", mitigationExpectedSchema, ""),
}

var mitigationResultSchema = goSchema{
	field("capability", nil, ""),
	field("contract_id", nil, ""),
	field("request_id", nil, ""),
	field("run_id", nil, ""),
	field("result_id", nil, ""),
	field("terminal_state", nil, ""),
	field("status", nil, ""),
	field("correlation_id", nil, "string"),
	field("result_ref", resultRefSchema, "pointer"),
	field("evidence_refs", nil, ""),
	field("request_sha256", nil, ""),
	field("upstream_inputs", nil, "raw"),
	field("input_provenance", mitigationProvenanceSchema, "pointer"),
	field("profile_id", nil, "string"),
	field("obligation_results", nil, "raw"),
	field("accounting", nil, "raw"),
	field("application_unit", nil, "raw"),
	field("match", nil, ""),
	field("expected", mitigationExpectedSchema, ""),
	field("actual", mitigationActualSchema, ""),
	field("substrate", mitigationSubstrateSchema, ""),
	field("candidate", mitigationCandidateSchema, "pointer"),
	field("test_basis", mitigationTestBasisSchema, "pointer"),
	field("steps", nil, ""),
	field("prose_summary", nil, ""),
	field("limitations", nil, "slice"),
	field("content_sha256", nil, "string"),
	field("size_bytes", nil, "number"),
	field("created_at", nil, ""),
}

var producerSchemas = map[string]goSchema{
	"defense":    defenseResultSchema,
	"mitigation": mitigationResultSchema,
}

// producerIntegrityBytes rebuilds the bytes the producer signed. The signature
// covers the result with its own integrity fields blanked, since they cannot
// be part of what they describe.
func producerIntegrityBytes(shape string, result map[string]any) ([]byte, error) {
	schema, known := producerSchemas[shape]
	if !known {
		return nil, fmt.Errorf("no producer schema for %s", shape)
	}
	unsigned := make(map[string]any, len(result)+2)
	for key, value := range result {
		unsigned[key] = value
	}
	unsigned["content_sha256"] = ""
	unsigned["size_bytes"] = json.Number("0")
	return goOrderedJSON(unsigned, schema)
}

// LocatorFor reports what a stored row must declare to authenticate: the
// digest over the reconstructed producer bytes, and their length. Callers that
// hold a row and want to know the locator it answers to -- a producer stamping
// one, or a test proving a row is the row that was signed -- go through this
// rather than re-deriving the reconstruction.
func LocatorFor(role string, result map[string]any) (ProducerLocator, error) {
	content, err := producerIntegrityBytes(producerShape(role), result)
	if err != nil {
		return ProducerLocator{}, err
	}
	digest := sha256.Sum256(content)
	return ProducerLocator{
		ContentSHA256: "sha256:" + hex.EncodeToString(digest[:]),
		SizeBytes:     len(content),
	}, nil
}

// goOrderedJSON encodes a decoded result the way encoding/json encoded it in
// the producer: declaration order, omitempty applied, and HTML escaping on --
// which is the opposite of internal/jsonx, where the goal is to match Python's
// json.dumps rather than Go's own default.
func goOrderedJSON(result map[string]any, schema goSchema) ([]byte, error) {
	var buffer bytes.Buffer
	if err := writeStruct(&buffer, result, schema); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func writeStruct(buffer *bytes.Buffer, value map[string]any, schema goSchema) error {
	buffer.WriteByte('{')
	first := true
	for _, entry := range schema {
		child, present := value[entry.name]
		// A field the stored row does not carry was omitted by the producer's
		// encoder too, so emitting a zero here would change the bytes.
		if !present || omitEmpty(child, entry.omitEmpty) {
			continue
		}
		if !first {
			buffer.WriteByte(',')
		}
		first = false
		if err := writeString(buffer, entry.name); err != nil {
			return err
		}
		buffer.WriteByte(':')
		if entry.omitEmpty == "raw" {
			if err := writeAny(buffer, child, nil); err != nil {
				return err
			}
			continue
		}
		if err := writeAny(buffer, child, entry.schema); err != nil {
			return err
		}
	}
	buffer.WriteByte('}')
	return nil
}

func writeAny(buffer *bytes.Buffer, value any, schema goSchema) error {
	switch typed := value.(type) {
	case []any:
		buffer.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := writeAny(buffer, item, schema); err != nil {
				return err
			}
		}
		buffer.WriteByte(']')
		return nil
	case map[string]any:
		if schema != nil {
			return writeStruct(buffer, typed, schema)
		}
		// No schema means the producer had a map here, and encoding/json
		// sorts map keys.
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buffer.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := writeString(buffer, key); err != nil {
				return err
			}
			buffer.WriteByte(':')
			if err := writeAny(buffer, typed[key], nil); err != nil {
				return err
			}
		}
		buffer.WriteByte('}')
		return nil
	default:
		return writeScalar(buffer, value)
	}
}

// writeScalar encodes a leaf with encoding/json, whose default escaping is
// what the producer used.
func writeScalar(buffer *bytes.Buffer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	buffer.Write(encoded)
	return nil
}

func writeString(buffer *bytes.Buffer, value string) error {
	return writeScalar(buffer, value)
}

func omitEmpty(value any, kind string) bool {
	switch kind {
	case "pointer", "raw":
		return value == nil
	case "string":
		text, ok := value.(string)
		return ok && text == ""
	case "slice":
		if value == nil {
			return true
		}
		items, ok := value.([]any)
		return ok && len(items) == 0
	case "number":
		return isZeroNumber(value)
	default:
		return false
	}
}

func isZeroNumber(value any) bool {
	switch typed := value.(type) {
	case json.Number:
		return typed.String() == "0"
	case float64:
		return typed == 0
	case int:
		return typed == 0
	default:
		return false
	}
}

// verifyProducerSignature authenticates a fetched row against the locator the
// caller supplied. A row whose bytes do not reproduce the declared digest is
// not the row the producer signed, whatever its lineage says.
func verifyProducerSignature(shape string, result map[string]any, locator ProducerLocator) error {
	if locator.ContentSHA256 == "" || shape == "" {
		return nil
	}
	content, err := producerIntegrityBytes(shape, result)
	if err != nil {
		return resolutionError("%s result could not be authenticated: %v", shape, err)
	}
	digest := sha256.Sum256(content)
	authenticated := "sha256:" + hex.EncodeToString(digest[:])
	if authenticated != locator.ContentSHA256 || (locator.SizeBytes > 0 && len(content) != locator.SizeBytes) {
		return resolutionError("%s authenticated bytes differ from the immutable locator", shape)
	}
	return nil
}

// ProducerLocator is the caller's declaration of what a row must hash to.
type ProducerLocator struct {
	ContentSHA256 string
	SizeBytes     int
}
