// Package jsonx provides insertion-ordered JSON objects and a Python-compatible
// compact encoder.
//
// The candidate artifact is serialized to a string, hashed, and returned as
// `content_ref`. Go's encoding/json sorts map keys and escapes HTML, while
// Python's json.dumps preserves dict insertion order and, with
// ensure_ascii=False, leaves <, > and & alone. Both services must produce the
// same bytes for the same rule, so ordered objects and this encoder are used
// wherever candidate content is built.
package jsonx

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Pair is one key/value entry in an ordered object.
type Pair struct {
	Key   string
	Value any
}

// Obj is a JSON object that marshals its keys in insertion order.
type Obj []Pair

// Set appends a key. Callers build objects in the order Python builds them.
func (o Obj) Set(key string, value any) Obj { return append(o, Pair{key, value}) }

// Get returns the value stored under key, and whether it was present.
func (o Obj) Get(key string) (any, bool) {
	for _, pair := range o {
		if pair.Key == key {
			return pair.Value, true
		}
	}
	return nil, false
}

// Replace overwrites an existing key in place, keeping its position.
func (o Obj) Replace(key string, value any) bool {
	for index := range o {
		if o[index].Key == key {
			o[index].Value = value
			return true
		}
	}
	return false
}

// MarshalJSON renders the object with its keys in insertion order.
func (o Obj) MarshalJSON() ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteByte('{')
	for index, pair := range o {
		if index > 0 {
			buffer.WriteByte(',')
		}
		key, err := Marshal(pair.Key)
		if err != nil {
			return nil, err
		}
		buffer.Write(key)
		buffer.WriteByte(':')
		value, err := Marshal(pair.Value)
		if err != nil {
			return nil, err
		}
		buffer.Write(value)
	}
	buffer.WriteByte('}')
	return buffer.Bytes(), nil
}

// Marshal encodes a value compactly without HTML escaping, matching
// json.dumps(..., ensure_ascii=False, separators=(",", ":")).
func Marshal(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	// Encode appends a newline that json.dumps does not produce.
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}

// MarshalString is Marshal returning a string.
func MarshalString(value any) (string, error) {
	encoded, err := Marshal(value)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// MustString returns the string stored under key, or "" when absent or of
// another type. Used where the builder guarantees a string was set.
func (o Obj) MustString(key string) string {
	if value, ok := o.Get(key); ok {
		if text, ok := value.(string); ok {
			return text
		}
	}
	return ""
}

// UnmarshalJSON decodes a JSON object while preserving its key order, so an
// envelope stored in SQLite round-trips byte-identically.
func (o *Obj) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return errors.New("jsonx: value is not a JSON object")
	}
	pairs := Obj{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("jsonx: object key is not a string")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		decoded, err := decodeAny(value)
		if err != nil {
			return err
		}
		pairs = append(pairs, Pair{Key: key, Value: decoded})
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	*o = pairs
	return nil
}

// decodeAny decodes a value, keeping nested objects ordered too.
func decodeAny(raw json.RawMessage) (any, error) {
	trimmed := bytes.TrimSpace(raw)
	switch {
	case len(trimmed) == 0:
		return nil, nil
	case trimmed[0] == '{':
		var nested Obj
		if err := nested.UnmarshalJSON(trimmed); err != nil {
			return nil, err
		}
		return nested, nil
	case trimmed[0] == '[':
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, err
		}
		values := make([]any, 0, len(items))
		for _, item := range items {
			decoded, err := decodeAny(item)
			if err != nil {
				return nil, err
			}
			values = append(values, decoded)
		}
		return values, nil
	default:
		var value any
		decoder := json.NewDecoder(bytes.NewReader(trimmed))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		return value, nil
	}
}
