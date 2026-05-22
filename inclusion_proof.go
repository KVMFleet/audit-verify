package main

// Inclusion-proof verification.
//
// What this file proves (and what it does NOT prove):
//
//   PROVES:
//     - Each row's `row_hash` matches SHA-256(prev_hash || canonical(payload)).
//       So the row content cannot be silently altered without breaking
//       the recomputation.
//     - Each row's Merkle path reconstructs the recorded epoch root.
//       So the row IS one of the rows the platform committed to in
//       that epoch's tree.
//
//   DOES NOT PROVE:
//     - That the chain between the included rows is contiguous. By
//       construction, a filtered export omits intermediate rows, so
//       `prev_hash` chains break. Run the verifier in the unfiltered
//       mode (--input) on a full export when you need continuity.
//     - That the epoch root itself was committed to by a witness or
//       signer. The customer authenticates roots separately via
//       --witness-pubkey / --signed-anchors / --check-against-anchor
//       on a full chain walk.
//
// Customers using the filtered-export feature get two artefacts:
//
//   - audit-filtered.ndjson — one JSON-line per row, same schema as
//     the unfiltered export, ONLY the rows the auditor needs.
//   - audit-filtered.proof   — JSON document carrying per-epoch
//     Merkle roots + per-event audit paths, as emitted by the
//     platform's POST /v1/audit/inclusion-proof endpoint.
//
// `kvmfleet-verify --filtered <ndjson> --proof <proof>` reads both,
// recomputes each row's row_hash from its prev_hash + canonical
// payload (same SHA-256-over-prev||canonical(payload) the chain
// uses), then verifies each Merkle inclusion proof against the
// recorded epoch root. A passing run means: every supplied row is
// cryptographically committed to inside the epoch root the platform
// claimed at build time.
//
// To close the loop on platform compromise, the customer should
// ALSO verify the epoch roots themselves against a witness-signed
// chain-anchor row (see --witness-pubkey, --signed-anchors). This
// file does NOT couple to those — `--filtered` proofs are valid
// regardless of how the customer authenticates the root.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

// ProofFile is the decoded shape of audit-filtered.proof.
type ProofFile struct {
	Events            []ProofEvent `json:"events"`
	Proofs            []ProofEpoch `json:"proofs"`
	NotCoveredEventID []int64      `json:"not_covered_event_ids"`
}

// ProofEvent is the per-event metadata in the proof file. Mirrors
// AuditEventOut from the platform but only the fields we need to
// recompute row_hash.
type ProofEvent struct {
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

// ProofEpoch is one Merkle epoch's worth of proofs.
type ProofEpoch struct {
	EpochDate     string             `json:"epoch_date"`
	MerkleRootHex string             `json:"merkle_root_hex"`
	TreeSize      int                `json:"tree_size"`
	Events        []EventInclusion   `json:"events"`
}

type EventInclusion struct {
	EventID   int64    `json:"event_id"`
	LeafIndex int      `json:"leaf_index"`
	PathHex   []string `json:"path_hex"`
}

// ParseProofFile reads + JSON-decodes a proof file. Returns a
// structured error so the CLI can fail fast with a precise message.
func ParseProofFile(r io.Reader) (*ProofFile, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	var p ProofFile
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("proof file is not valid JSON: %w", err)
	}
	// Cheap structural validation.
	for i, ep := range p.Proofs {
		if len(ep.MerkleRootHex) != 64 {
			return nil, fmt.Errorf("proof[%d]: merkle_root_hex must be 64 hex chars; got %d", i, len(ep.MerkleRootHex))
		}
		if ep.TreeSize < 1 {
			return nil, fmt.Errorf("proof[%d]: tree_size must be >= 1; got %d", i, ep.TreeSize)
		}
	}
	return &p, nil
}

// InclusionResult is the outcome of verifying every proof in a file.
type InclusionResult struct {
	TotalEvents     int
	VerifiedEvents  int
	Failures        []string
}

func (r *InclusionResult) HasAnyFailures() bool {
	return len(r.Failures) > 0
}

// VerifyInclusionProofs walks every (epoch, event) pair and checks
// the Merkle path against the recorded root, AND verifies the
// recomputed row_hash matches the event's claimed row_hash (so a
// fabricated event with a forged path-to-some-root still fails).
func VerifyInclusionProofs(p *ProofFile) InclusionResult {
	res := InclusionResult{}
	// Build a quick lookup: event_id → event payload.
	byID := map[int64]*ProofEvent{}
	for i := range p.Events {
		byID[p.Events[i].ID] = &p.Events[i]
	}

	for _, epoch := range p.Proofs {
		root, err := hex.DecodeString(epoch.MerkleRootHex)
		if err != nil || len(root) != 32 {
			res.Failures = append(res.Failures,
				fmt.Sprintf("epoch %s: merkle_root_hex malformed", epoch.EpochDate))
			continue
		}
		for _, inc := range epoch.Events {
			res.TotalEvents++
			ev, ok := byID[inc.EventID]
			if !ok {
				res.Failures = append(res.Failures,
					fmt.Sprintf("epoch %s event %d: not present in events array",
						epoch.EpochDate, inc.EventID))
				continue
			}
			// Recompute row_hash from prev_hash + canonical payload —
			// same code path the unfiltered verifier uses, lifted
			// inline so this file is self-contained.
			prev, err := hex.DecodeString(ev.PrevHash)
			if err != nil || len(prev) != 32 {
				res.Failures = append(res.Failures,
					fmt.Sprintf("event %d: malformed prev_hash", ev.ID))
				continue
			}
			payload := map[string]any{
				"org_id":      ev.OrgID,
				"occurred_at": ev.OccurredAt,
				"actor_type":  ev.ActorType,
				"actor_id":    ev.ActorID,
				"action":      ev.Action,
				"target_type": derefStringPtr(ev.TargetType),
				"target_id":   derefStringPtr(ev.TargetID),
				"result":      ev.Result,
				"details":     emptyMapIfNil(ev.Details),
			}
			canon, err := canonical(payload)
			if err != nil {
				res.Failures = append(res.Failures,
					fmt.Sprintf("event %d: canonical encode failed: %v", ev.ID, err))
				continue
			}
			h := sha256.New()
			h.Write(prev)
			h.Write(canon)
			gotRowHash := h.Sum(nil)
			claimed, err := hex.DecodeString(ev.RowHash)
			if err != nil || !bytesEqual(gotRowHash, claimed) {
				res.Failures = append(res.Failures,
					fmt.Sprintf("event %d: row_hash mismatch — event body has been altered",
						ev.ID))
				continue
			}
			// Walk the Merkle path. leaf data = row_hash bytes.
			path := make([][]byte, 0, len(inc.PathHex))
			pathOK := true
			for _, ph := range inc.PathHex {
				pb, err := hex.DecodeString(ph)
				if err != nil || len(pb) != 32 {
					res.Failures = append(res.Failures,
						fmt.Sprintf("event %d: path entry malformed", ev.ID))
					pathOK = false
					break
				}
				path = append(path, pb)
			}
			if !pathOK {
				continue
			}
			if !verifyInclusion(gotRowHash, inc.LeafIndex, epoch.TreeSize, path, root) {
				res.Failures = append(res.Failures,
					fmt.Sprintf("event %d: Merkle inclusion proof FAILED for epoch %s",
						ev.ID, epoch.EpochDate))
				continue
			}
			res.VerifiedEvents++
		}
	}
	return res
}

func derefStringPtr(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func emptyMapIfNil(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}
