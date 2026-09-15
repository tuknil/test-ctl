package storetest

import "encoding/json"

// The list projection reads scalar paths out of stored JSON, the way the
// Databricks colon operator does.
func jsonPath(document string, path ...string) string {
	var node any
	if json.Unmarshal([]byte(document), &node) != nil {
		return ""
	}
	// The stored envelope wraps the business result.
	if object, ok := node.(map[string]any); ok {
		if structured, present := object["structured_result"]; present {
			node = structured
		}
	}
	for _, segment := range path {
		object, ok := node.(map[string]any)
		if !ok {
			return ""
		}
		if node, ok = object[segment]; !ok {
			return ""
		}
	}
	text, _ := node.(string)
	return text
}

func artifactType(document string) string {
	return jsonPath(document, "primary_candidate", "candidate_artifact", "artifact_type")
}
