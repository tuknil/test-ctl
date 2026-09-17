package upstream

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The producer signs its result with content_sha256 over the bytes
// encoding/json produced. Databricks normalizes the stored JSON, so the row
// read back is not those bytes and has to be reconstructed before the
// signature means anything.

func decodeSample(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/defense_generation_result.json")
	if err != nil {
		t.Fatalf("unable to read the sample: %v", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		t.Fatalf("the sample is not valid JSON: %v", err)
	}
	return result
}

func digestOf(t *testing.T, content []byte) string {
	t.Helper()
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// The digest below was produced by running this exact sample through the
// Python reader's _producer_integrity_bytes. Both services authenticate the
// same rows, so a change on either side that moves these bytes is a change
// that starts rejecting good rows -- this is the test that catches it.
const pythonReconstructionDigest = "sha256:4aaf081218584c4cbbc0a37b8310a5f42e9146bf0597b87909943511c0efcc87"

func TestReconstructionMatchesThePythonReaderByte(t *testing.T) {
	content, err := producerIntegrityBytes("defense", decodeSample(t))
	if err != nil {
		t.Fatalf("reconstruction failed: %v", err)
	}

	if got := digestOf(t, content); got != pythonReconstructionDigest {
		t.Errorf("reconstruction diverged from the Python reader\n got: %s\nwant: %s", got, pythonReconstructionDigest)
	}
	if len(content) != 1539 {
		t.Errorf("reconstruction is %d bytes, want 1539", len(content))
	}
}

// encoding/json escapes these by default. internal/jsonx deliberately turns
// that off to match Python's json.dumps; here the goal is the opposite, and
// getting it backwards would silently fail every row carrying one.
func TestReconstructionEscapesTheWayEncodingJSONDoes(t *testing.T) {
	content, err := producerIntegrityBytes("defense", decodeSample(t))
	if err != nil {
		t.Fatalf("reconstruction failed: %v", err)
	}
	text := string(content)

	for raw, escaped := range map[string]string{
		"&": `\u0026`,
		"<": `\u003c`,
		">": `\u003e`,
	} {
		if !strings.Contains(text, escaped) {
			t.Errorf("%s should be written as %s", raw, escaped)
		}
		if strings.Contains(text, raw) {
			t.Errorf("a raw %s survived unescaped", raw)
		}
	}
}

// A field the stored row omitted was omitted by the producer's encoder too.
// Emitting a zero for it would change the bytes, which is why this walks a
// schema rather than round-tripping a struct.
func TestAbsentFieldsAreNotEmittedAsZeroes(t *testing.T) {
	result := decodeSample(t)
	delete(result, "prose_summary")

	content, err := producerIntegrityBytes("defense", result)
	if err != nil {
		t.Fatalf("reconstruction failed: %v", err)
	}

	if strings.Contains(string(content), "prose_summary") {
		t.Error("an absent field was emitted")
	}
}

// The integrity fields cannot be part of what they describe, so they are
// blanked first -- and because the producer declares them omitempty, blanking
// drops them from the bytes entirely rather than writing an empty one.
func TestIntegrityFieldsAreBlankedBeforeHashing(t *testing.T) {
	sample := decodeSample(t)
	if sample["content_sha256"] == "" || sample["size_bytes"] == nil {
		t.Fatal("the sample must carry integrity fields for this to prove anything")
	}

	content, err := producerIntegrityBytes("defense", sample)
	if err != nil {
		t.Fatalf("reconstruction failed: %v", err)
	}
	text := string(content)

	if strings.Contains(text, "content_sha256") {
		t.Error("the declared digest was hashed into its own value")
	}
	if strings.Contains(text, "4242") || strings.Contains(text, "size_bytes") {
		t.Error("the declared size was hashed into its own digest")
	}
}

// Field order is the producer struct's declaration order, not sorted.
func TestFieldOrderFollowsTheProducerStruct(t *testing.T) {
	content, err := producerIntegrityBytes("defense", decodeSample(t))
	if err != nil {
		t.Fatalf("reconstruction failed: %v", err)
	}
	text := string(content)

	capability := strings.Index(text, `"capability"`)
	contract := strings.Index(text, `"contract_id"`)
	if capability == -1 || contract == -1 || capability > contract {
		t.Error("capability must precede contract_id, as the struct declares them")
	}
	// Sorted order would put capability after attempt_history.
	if attempts := strings.Index(text, `"attempt_history"`); attempts != -1 && attempts < capability {
		t.Error("fields came out sorted rather than in declaration order")
	}
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

func TestVerificationAcceptsARowThatReproducesItsLocator(t *testing.T) {
	result := decodeSample(t)
	content, _ := producerIntegrityBytes("defense", result)
	locator := ProducerLocator{ContentSHA256: digestOf(t, content), SizeBytes: len(content)}

	if err := verifyProducerSignature("defense", result, locator); err != nil {
		t.Errorf("a matching row should authenticate: %v", err)
	}
}

// A row whose bytes do not reproduce the declared digest is not the row the
// producer signed, whatever its lineage says.
func TestVerificationRejectsATamperedRow(t *testing.T) {
	result := decodeSample(t)
	content, _ := producerIntegrityBytes("defense", result)
	locator := ProducerLocator{ContentSHA256: digestOf(t, content), SizeBytes: len(content)}

	// The rule itself is what this service goes on to compile.
	candidate := result["primary_candidate"].(map[string]any)
	candidate["artifact_content"] = `SecRule ARGS "@rx something-else" "id:1,deny"`

	err := verifyProducerSignature("defense", result, locator)

	if err == nil || !strings.Contains(err.Error(), "differ from the immutable locator") {
		t.Fatalf("err = %v, want an authentication failure", err)
	}
}

func TestVerificationRejectsASizeMismatch(t *testing.T) {
	result := decodeSample(t)
	content, _ := producerIntegrityBytes("defense", result)
	locator := ProducerLocator{ContentSHA256: digestOf(t, content), SizeBytes: len(content) + 1}

	if err := verifyProducerSignature("defense", result, locator); err == nil {
		t.Error("a declared size that does not match must fail")
	}
}

// A caller that predates the signed contract sends no digest, and its rows
// still resolve on lineage alone.
func TestVerificationIsSkippedWithoutALocator(t *testing.T) {
	if err := verifyProducerSignature("defense", decodeSample(t), ProducerLocator{}); err != nil {
		t.Errorf("an unsigned locator should not fail: %v", err)
	}
}

// Bypass Validation results have no reconstruction schema here, the same as in
// the Python reader, so a locator on that role is not enforced rather than
// being failed with a digest nobody can compute.
func TestVerificationIsSkippedForAnUnschemedShape(t *testing.T) {
	locator := ProducerLocator{ContentSHA256: pythonReconstructionDigest, SizeBytes: 10}

	if err := verifyProducerSignature(producerShape(roleBypass), decodeSample(t), locator); err != nil {
		t.Errorf("an unschemed shape should be skipped, not failed: %v", err)
	}
}
