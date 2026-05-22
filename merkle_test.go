package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// Cross-language parity. This MUST match
// platform/tests/test_merkle.py::test_rfc6962_known_seven_leaf_root.
// Any drift means a customer's filtered proof verifies on one side
// but fails on the other — a silent break we must not ship.
func TestMerkleRoot_CrossLanguageFixture(t *testing.T) {
	leaves := make([][]byte, 7)
	for i := 0; i < 7; i++ {
		leaves[i] = []byte(fmt.Sprintf("leaf-%d", i))
	}
	root := merkleTreeHash(leaves)
	expected := "0b007fb915eb9b2a146f54b1c86ec53b664f8e455b7660b0b6ee13edc0d921c0"
	if hex.EncodeToString(root) != expected {
		t.Fatalf("cross-language root drift: got %s want %s",
			hex.EncodeToString(root), expected)
	}
}

func TestEmptyRoot_IsSha256OfEmptyString(t *testing.T) {
	exp := sha256.Sum256(nil)
	if !bytesEqual(emptyRoot, exp[:]) {
		t.Fatalf("emptyRoot != SHA-256(\"\")")
	}
}

func TestVerifyInclusion_RoundTripsForEverySize(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 8, 13, 17} {
		leaves := make([][]byte, n)
		for i := 0; i < n; i++ {
			leaves[i] = []byte(fmt.Sprintf("x%d", i))
		}
		root := merkleTreeHash(leaves)
		for i := 0; i < n; i++ {
			path := auditPath(leaves, i)
			leafBytes := leaves[i]
			if !verifyInclusion(leafBytes, i, n, path, root) {
				t.Errorf("verify failed at n=%d i=%d", n, i)
			}
		}
	}
}

func TestVerifyInclusion_RejectsWrongRoot(t *testing.T) {
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	root := merkleTreeHash(leaves)
	path := auditPath(leaves, 1)
	bad := make([]byte, len(root))
	copy(bad, root)
	bad[0] ^= 0xff
	if verifyInclusion(leaves[1], 1, 4, path, bad) {
		t.Fatalf("verify accepted wrong root")
	}
}

func TestVerifyInclusion_RejectsWrongLeaf(t *testing.T) {
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	root := merkleTreeHash(leaves)
	path := auditPath(leaves, 1)
	if verifyInclusion([]byte("NOT b"), 1, 4, path, root) {
		t.Fatalf("verify accepted wrong leaf")
	}
}

func TestParseProofFile_RejectsMalformed(t *testing.T) {
	cases := []string{
		`{`,                                   // bad JSON
		`{"proofs":[{"merkle_root_hex":"ab","tree_size":1,"events":[]}]}`, // short root
		`{"proofs":[{"merkle_root_hex":"` + strings.Repeat("a", 64) + `","tree_size":0,"events":[]}]}`, // tree_size=0
	}
	for _, c := range cases {
		_, err := ParseProofFile(strings.NewReader(c))
		if err == nil {
			t.Errorf("expected error for input %q, got nil", c)
		}
	}
}

func TestVerifyInclusionProofs_HappyPath(t *testing.T) {
	// Build a small in-memory chain to provide a self-consistent
	// proof file: two events with row_hash chained from ZERO_HASH.
	prev := make([]byte, 32) // ZERO_HASH
	payload1 := map[string]any{
		"org_id":      "00000000-0000-0000-0000-000000000001",
		"occurred_at": "2026-05-22T12:00:00+00:00",
		"actor_type":  "user", "actor_id": "u1",
		"action": "login.success", "result": "success",
		"target_type": nil, "target_id": nil, "details": map[string]any{},
	}
	canon1, _ := canonical(payload1)
	h1 := sha256.New()
	h1.Write(prev)
	h1.Write(canon1)
	row1 := h1.Sum(nil)

	prev = row1
	payload2 := map[string]any{
		"org_id":      "00000000-0000-0000-0000-000000000001",
		"occurred_at": "2026-05-22T12:00:01+00:00",
		"actor_type":  "user", "actor_id": "u1",
		"action": "session.start", "result": "success",
		"target_type": nil, "target_id": nil, "details": map[string]any{},
	}
	canon2, _ := canonical(payload2)
	h2 := sha256.New()
	h2.Write(prev)
	h2.Write(canon2)
	row2 := h2.Sum(nil)

	leaves := [][]byte{row1, row2}
	root := merkleTreeHash(leaves)

	pf := &ProofFile{
		Events: []ProofEvent{
			{ID: 1, OrgID: "00000000-0000-0000-0000-000000000001",
				OccurredAt: "2026-05-22T12:00:00+00:00",
				ActorType:  "user", ActorID: "u1",
				Action: "login.success", Result: "success",
				Details:  map[string]any{},
				RowHash:  hex.EncodeToString(row1),
				PrevHash: hex.EncodeToString(make([]byte, 32))},
			{ID: 2, OrgID: "00000000-0000-0000-0000-000000000001",
				OccurredAt: "2026-05-22T12:00:01+00:00",
				ActorType:  "user", ActorID: "u1",
				Action: "session.start", Result: "success",
				Details:  map[string]any{},
				RowHash:  hex.EncodeToString(row2),
				PrevHash: hex.EncodeToString(row1)},
		},
		Proofs: []ProofEpoch{{
			EpochDate:     "2026-05-22",
			MerkleRootHex: hex.EncodeToString(root),
			TreeSize:      2,
			Events: []EventInclusion{
				{EventID: 1, LeafIndex: 0,
					PathHex: []string{hex.EncodeToString(auditPath(leaves, 0)[0])}},
				{EventID: 2, LeafIndex: 1,
					PathHex: []string{hex.EncodeToString(auditPath(leaves, 1)[0])}},
			},
		}},
	}
	res := VerifyInclusionProofs(pf)
	if res.HasAnyFailures() {
		t.Fatalf("unexpected failures: %+v", res)
	}
	if res.VerifiedEvents != 2 {
		t.Fatalf("expected 2 verified, got %d", res.VerifiedEvents)
	}
}

func TestVerifyInclusionProofs_DetectsTamperedRow(t *testing.T) {
	// Build a 1-leaf tree, then mutate the event's action.
	prev := make([]byte, 32)
	payload := map[string]any{
		"org_id":      "00000000-0000-0000-0000-000000000001",
		"occurred_at": "2026-05-22T12:00:00+00:00",
		"actor_type":  "user", "actor_id": "u1",
		"action": "login.success", "result": "success",
		"target_type": nil, "target_id": nil, "details": map[string]any{},
	}
	canon, _ := canonical(payload)
	h := sha256.New()
	h.Write(prev)
	h.Write(canon)
	row := h.Sum(nil)
	root := merkleTreeHash([][]byte{row})

	pf := &ProofFile{
		Events: []ProofEvent{{
			ID: 1, OrgID: "00000000-0000-0000-0000-000000000001",
			OccurredAt: "2026-05-22T12:00:00+00:00",
			ActorType:  "user", ActorID: "u1",
			Action: "login.MALICIOUS", // <-- altered
			Result: "success",
			Details:  map[string]any{},
			RowHash:  hex.EncodeToString(row),
			PrevHash: hex.EncodeToString(prev),
		}},
		Proofs: []ProofEpoch{{
			EpochDate:     "2026-05-22",
			MerkleRootHex: hex.EncodeToString(root),
			TreeSize:      1,
			Events: []EventInclusion{{
				EventID: 1, LeafIndex: 0, PathHex: nil,
			}},
		}},
	}
	res := VerifyInclusionProofs(pf)
	if !res.HasAnyFailures() {
		t.Fatalf("expected row_hash mismatch failure")
	}
}
