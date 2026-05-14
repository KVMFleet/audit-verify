package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Fixtures here are byte-exact outputs of Python's
//
//	json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
//
// which is what the platform hashes over. Any Go canonical drift would
// shift the hash and break verification — these tests are the regression
// guard.

func TestCanonical_BasicPayload(t *testing.T) {
	payload := map[string]any{
		"org_id":      "550e8400-e29b-41d4-a716-446655440000",
		"occurred_at": "2026-05-14T10:00:00+00:00",
		"actor_type":  "user",
		"actor_id":    "alice",
		"action":      "console.start",
		"target_type": "device",
		"target_id":   "device-1",
		"result":      "ok",
		"details":     map[string]any{},
	}
	want := `{"action":"console.start","actor_id":"alice","actor_type":"user","details":{},"occurred_at":"2026-05-14T10:00:00+00:00","org_id":"550e8400-e29b-41d4-a716-446655440000","result":"ok","target_id":"device-1","target_type":"device"}`

	got, err := canonical(payload)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if string(got) != want {
		t.Errorf("mismatch.\nwant: %s\ngot : %s", want, string(got))
	}
}

func TestCanonical_NilTargets(t *testing.T) {
	payload := map[string]any{
		"org_id":      "org-1",
		"occurred_at": "2026-05-14T10:00:00+00:00",
		"actor_type":  "system",
		"actor_id":    "janitor",
		"action":      "audit.retention.swept",
		"target_type": nil,
		"target_id":   nil,
		"result":      "ok",
		"details":     map[string]any{},
	}
	want := `{"action":"audit.retention.swept","actor_id":"janitor","actor_type":"system","details":{},"occurred_at":"2026-05-14T10:00:00+00:00","org_id":"org-1","result":"ok","target_id":null,"target_type":null}`

	got, err := canonical(payload)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if string(got) != want {
		t.Errorf("mismatch.\nwant: %s\ngot : %s", want, string(got))
	}
}

func TestCanonical_StringEscapes(t *testing.T) {
	// Byte-exact output Python emits for:
	//    json.dumps({"s": "\"\\\n\t\x01é🙂"}, separators=(",", ":"))
	// with ensure_ascii=True (the default). 'é' becomes é; '🙂'
	// (U+1F642) becomes the UTF-16 surrogate pair 🙂.
	got, err := canonical(map[string]any{"s": "\"\\\n\t\x01é🙂"})
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	want := `{"s":"\"\\\n\t\u0001\u00e9\ud83d\ude42"}`
	if string(got) != want {
		t.Errorf("mismatch.\nwant: %s\ngot : %s", want, string(got))
	}
}

func TestCanonical_NumbersFromJSONNumber(t *testing.T) {
	in := `{"int":1,"float":1.0,"neg":-3,"sci":1e2}`
	dec := json.NewDecoder(strings.NewReader(in))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, err := canonical(v)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	want := `{"float":1.0,"int":1,"neg":-3,"sci":1e2}`
	if string(got) != want {
		t.Errorf("mismatch.\nwant: %s\ngot : %s", want, string(got))
	}
}

func TestCanonical_NestedSortedKeys(t *testing.T) {
	payload := map[string]any{
		"z": map[string]any{
			"b": 2,
			"a": 1,
		},
		"a": []any{
			map[string]any{"y": "Y", "x": "X"},
		},
	}
	want := `{"a":[{"x":"X","y":"Y"}],"z":{"a":1,"b":2}}`

	got, err := canonical(payload)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if string(got) != want {
		t.Errorf("mismatch.\nwant: %s\ngot : %s", want, string(got))
	}
}

func TestCanonical_HTMLChars(t *testing.T) {
	// Python doesn't HTML-escape <, >, &. Go must not either.
	got, err := canonical(map[string]any{"s": "<a>&b</a>"})
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	want := `{"s":"<a>&b</a>"}`
	if string(got) != want {
		t.Errorf("mismatch.\nwant: %s\ngot : %s", want, string(got))
	}
}
