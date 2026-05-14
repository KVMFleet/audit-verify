package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// auditEvent mirrors one line of the platform's /v1/audit/events.ndjson
// export. Numeric fields use json.Number so the canonical encoder can
// emit them verbatim, preserving the int-vs-float distinction the
// platform hashed at write time.
type auditEvent struct {
	ID         int64          `json:"id"`
	OrgID      string         `json:"org_id"`
	OccurredAt string         `json:"occurred_at"`
	ActorType  string         `json:"actor_type"`
	ActorID    string         `json:"actor_id"`
	Action     string         `json:"action"`
	TargetType *string        `json:"target_type"`
	TargetID   *string        `json:"target_id"`
	Result     string         `json:"result"`
	Details    map[string]any `json:"details"`
	RowHash    string         `json:"row_hash"`
	PrevHash   string         `json:"prev_hash"`
}

// VerifyResult is the outcome of walking the chain end-to-end.
type VerifyResult struct {
	Checked      int
	OK           bool
	FirstBreakID int64  // 0 if OK
	Message      string // human-readable
	ChainHead    string // hex of the final row_hash (only meaningful when OK)
}

// Verify walks an NDJSON stream, recomputing each event's row_hash from
// prev_hash + canonical(payload), and stops at the first mismatch.
//
// anchor must be 32 raw bytes (the org's audit_chain_anchor, default
// 32 × 0x00). On a brand-new org or one that's never had a retention
// sweep, anchor == ZERO_HASH.
func Verify(r io.Reader, anchor [32]byte) (VerifyResult, error) {
	prev := anchor[:]
	checked := 0
	sc := bufio.NewScanner(r)
	// Large enough for any plausibly-sized audit event line (details
	// is JSONB, can hold sizeable payloads).
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 || (len(line) == 1 && line[0] == '\n') {
			continue
		}

		// Decode with UseNumber() so numeric values in `details`
		// preserve their original JSON-source representation when
		// we re-emit them in the canonical form.
		ev, err := decodeEvent(line)
		if err != nil {
			return VerifyResult{
				Checked: checked, OK: false,
				Message: fmt.Sprintf("malformed NDJSON at line %d: %v", checked+1, err),
			}, nil
		}

		prevHashBytes, err := hex.DecodeString(ev.PrevHash)
		if err != nil || len(prevHashBytes) != 32 {
			return VerifyResult{
				Checked: checked + 1, OK: false, FirstBreakID: ev.ID,
				Message: fmt.Sprintf("malformed prev_hash at id=%d", ev.ID),
			}, nil
		}

		if !bytesEqual(prevHashBytes, prev) {
			return VerifyResult{
				Checked: checked + 1, OK: false, FirstBreakID: ev.ID,
				Message: fmt.Sprintf("prev_hash mismatch at id=%d (expected %s, got %s)",
					ev.ID, hex.EncodeToString(prev), ev.PrevHash),
			}, nil
		}

		// Reconstruct the exact dict the platform hashed.
		payload := map[string]any{
			"org_id":      ev.OrgID,
			"occurred_at": ev.OccurredAt,
			"actor_type":  ev.ActorType,
			"actor_id":    ev.ActorID,
			"action":      ev.Action,
			"target_type": derefOrNil(ev.TargetType),
			"target_id":   derefOrNil(ev.TargetID),
			"result":      ev.Result,
			"details":     emptyIfNil(ev.Details),
		}
		canon, err := canonical(payload)
		if err != nil {
			return VerifyResult{}, fmt.Errorf("canonical encode at id=%d: %w", ev.ID, err)
		}

		h := sha256.New()
		h.Write(prev)
		h.Write(canon)
		got := h.Sum(nil)

		gotRowHash, err := hex.DecodeString(ev.RowHash)
		if err != nil || len(gotRowHash) != 32 {
			return VerifyResult{
				Checked: checked + 1, OK: false, FirstBreakID: ev.ID,
				Message: fmt.Sprintf("malformed row_hash at id=%d", ev.ID),
			}, nil
		}

		if !bytesEqual(got, gotRowHash) {
			return VerifyResult{
				Checked: checked + 1, OK: false, FirstBreakID: ev.ID,
				Message: fmt.Sprintf("row_hash mismatch at id=%d (expected %s, got %s)",
					ev.ID, hex.EncodeToString(got), ev.RowHash),
			}, nil
		}

		prev = gotRowHash
		checked++
	}
	if err := sc.Err(); err != nil {
		return VerifyResult{}, fmt.Errorf("read input: %w", err)
	}

	return VerifyResult{
		Checked: checked, OK: true,
		Message:   fmt.Sprintf("OK %d events", checked),
		ChainHead: hex.EncodeToString(prev),
	}, nil
}

func decodeEvent(line []byte) (auditEvent, error) {
	dec := json.NewDecoder(strings.NewReader(string(line)))
	dec.UseNumber()
	var ev auditEvent
	if err := dec.Decode(&ev); err != nil {
		return ev, err
	}
	return ev, nil
}

func derefOrNil(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func emptyIfNil(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
