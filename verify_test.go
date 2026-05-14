package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// Build a synthetic chain from in-memory events using the same canonical
// + SHA-256 algorithm the platform uses, then feed the resulting NDJSON
// into Verify and assert it walks clean.

type rawEvent struct {
	ID         int64
	OrgID      string
	OccurredAt string
	ActorType  string
	ActorID    string
	Action     string
	TargetType *string
	TargetID   *string
	Result     string
	Details    map[string]any
}

func buildChain(t *testing.T, anchor [32]byte, events []rawEvent) string {
	t.Helper()
	var b strings.Builder
	prev := anchor[:]
	for _, e := range events {
		payload := map[string]any{
			"org_id":      e.OrgID,
			"occurred_at": e.OccurredAt,
			"actor_type":  e.ActorType,
			"actor_id":    e.ActorID,
			"action":      e.Action,
			"target_type": derefOrNil(e.TargetType),
			"target_id":   derefOrNil(e.TargetID),
			"result":      e.Result,
			"details":     emptyIfNil(e.Details),
		}
		canon, err := canonical(payload)
		if err != nil {
			t.Fatalf("canonical: %v", err)
		}
		h := sha256.New()
		h.Write(prev)
		h.Write(canon)
		row := h.Sum(nil)

		line := map[string]any{
			"id":          e.ID,
			"org_id":      e.OrgID,
			"occurred_at": e.OccurredAt,
			"actor_type":  e.ActorType,
			"actor_id":    e.ActorID,
			"action":      e.Action,
			"target_type": derefOrNil(e.TargetType),
			"target_id":   derefOrNil(e.TargetID),
			"result":      e.Result,
			"details":     emptyIfNil(e.Details),
			"row_hash":    hex.EncodeToString(row),
			"prev_hash":   hex.EncodeToString(prev),
		}
		buf, err := json.Marshal(line)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		b.Write(buf)
		b.WriteByte('\n')
		prev = row
	}
	return b.String()
}

func sampleEvents() []rawEvent {
	dev := "device-1"
	user := "user"
	usr := "alice"
	return []rawEvent{
		{
			ID: 1, OrgID: "550e8400-e29b-41d4-a716-446655440000",
			OccurredAt: "2026-05-14T10:00:00+00:00",
			ActorType:  user, ActorID: usr,
			Action: "user.login", Result: "ok",
		},
		{
			ID: 2, OrgID: "550e8400-e29b-41d4-a716-446655440000",
			OccurredAt: "2026-05-14T10:00:05+00:00",
			ActorType:  user, ActorID: usr,
			Action: "console.start", Result: "ok",
			TargetType: strPtr("device"), TargetID: &dev,
			Details: map[string]any{"session_id": "abc-123", "reason": "patching"},
		},
		{
			ID: 3, OrgID: "550e8400-e29b-41d4-a716-446655440000",
			OccurredAt: "2026-05-14T10:10:00+00:00",
			ActorType:  user, ActorID: usr,
			Action: "console.end", Result: "ok",
			TargetType: strPtr("device"), TargetID: &dev,
			Details: map[string]any{"session_id": "abc-123", "duration_s": 600, "end_reason": "user"},
		},
	}
}

func strPtr(s string) *string { return &s }

func TestVerify_HappyPath(t *testing.T) {
	var anchor [32]byte
	ndjson := buildChain(t, anchor, sampleEvents())
	res, err := Verify(strings.NewReader(ndjson), anchor)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("chain failed: %s", res.Message)
	}
	if res.Checked != 3 {
		t.Errorf("expected 3 events, got %d", res.Checked)
	}
}

func TestVerify_DetectsTamperedDetails(t *testing.T) {
	var anchor [32]byte
	ndjson := buildChain(t, anchor, sampleEvents())
	// Flip a character inside event 2's details — this changes the
	// recomputed hash but the row_hash on the line is still the
	// original, so we should detect a row_hash mismatch at id=2.
	tampered := strings.Replace(ndjson, `"reason":"patching"`, `"reason":"pwning  "`, 1)
	if tampered == ndjson {
		t.Fatal("test setup: substitution didn't apply")
	}
	res, err := Verify(strings.NewReader(tampered), anchor)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("expected break, got OK")
	}
	if res.FirstBreakID != 2 {
		t.Errorf("expected break at id=2, got id=%d (msg=%s)", res.FirstBreakID, res.Message)
	}
}

func TestVerify_DetectsBrokenPrev(t *testing.T) {
	var anchor [32]byte
	ndjson := buildChain(t, anchor, sampleEvents())
	// Delete the first event — event 2's prev_hash will no longer
	// match the seed (anchor).
	lines := strings.SplitN(ndjson, "\n", 2)
	rest := lines[1]
	res, err := Verify(strings.NewReader(rest), anchor)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("expected break, got OK")
	}
	if res.FirstBreakID != 2 {
		t.Errorf("expected break at id=2, got id=%d (msg=%s)", res.FirstBreakID, res.Message)
	}
	if !strings.Contains(res.Message, "prev_hash mismatch") {
		t.Errorf("expected prev_hash mismatch message; got: %s", res.Message)
	}
}

func TestVerify_NonZeroAnchorAfterRetentionSweep(t *testing.T) {
	// Simulate the post-retention-sweep case: anchor is the row_hash
	// of the last-deleted row, and the surviving chain still verifies
	// forward from that point.
	var initial [32]byte
	full := buildChain(t, initial, sampleEvents())
	lines := strings.Split(strings.TrimSpace(full), "\n")

	// Extract event 1's row_hash from its NDJSON line — that becomes
	// our anchor after a sweep deletes event 1.
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	anchorHex := first["row_hash"].(string)
	anchorBytes, _ := hex.DecodeString(anchorHex)
	var anchor [32]byte
	copy(anchor[:], anchorBytes)

	// Feed only events 2 + 3 and verify with anchor = event 1's hash.
	rest := strings.Join(lines[1:], "\n") + "\n"
	res, err := Verify(strings.NewReader(rest), anchor)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("post-sweep chain failed: %s", res.Message)
	}
	if res.Checked != 2 {
		t.Errorf("expected 2 events after sweep, got %d", res.Checked)
	}
}

func TestVerify_EmptyInputIsOK(t *testing.T) {
	var anchor [32]byte
	res, err := Verify(strings.NewReader(""), anchor)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Errorf("empty input should be OK; got: %s", res.Message)
	}
	if res.Checked != 0 {
		t.Errorf("expected 0 events, got %d", res.Checked)
	}
}
