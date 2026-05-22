package main

// Verifier-side support for the platform's configurable witness
// endpoints (audit_witnesses on the platform side).
//
// The platform POSTs each chain anchor to every configured witness and
// embeds the responses inside the `audit.chain.anchor` event's
// `details.witness_responses` array. This file walks an NDJSON export,
// extracts every witness response, and (when the customer hands us
// pubkeys via --witness-pubkey name:hex) Ed25519-verifies each
// signature against the (chain_head_bytes || witness_timestamp) blob.
//
// Threat model closed by this check: a platform-popped attacker can
// rewrite audit_events forward, but they cannot forge witness
// signatures (they don't have the witnesses' private keys). For every
// signed anchor an attacker leaves intact, the historical chain head
// is locked in — any rewrite that removes that chain head fails the
// "head appeared in walk" check.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// WitnessKey holds one (witness-name, pubkey) pair supplied by the
// customer via --witness-pubkey. The customer is the source of truth
// for which witnesses they trust and what pubkeys those witnesses
// publish — the platform's audit log only carries hashes/signatures,
// never the pubkeys themselves.
type WitnessKey struct {
	Name   string
	Pubkey ed25519.PublicKey
}

// ParseWitnessKeyFlag turns the repeated --witness-pubkey "name:hex"
// CLI flag into a typed list. Returns a structured error on bad
// format so main.go can fail fast before walking input.
//
// Names are compared case-sensitively against the witness names the
// platform recorded in details.witness_responses[*].name. A mismatch
// (different casing, typo) silently skips that anchor's verification
// — by design, since the customer may legitimately want to check only
// a subset of witnesses. Run `kvmfleet-verify` once without
// --witness-pubkey first to print the names the chain actually
// contains.
func ParseWitnessKeyFlag(values []string) ([]WitnessKey, error) {
	out := make([]WitnessKey, 0, len(values))
	seen := map[string]bool{}
	for _, v := range values {
		idx := strings.IndexByte(v, ':')
		if idx <= 0 || idx == len(v)-1 {
			return nil, fmt.Errorf("--witness-pubkey value %q must be of the form name:hex", v)
		}
		name := strings.TrimSpace(v[:idx])
		hexstr := strings.ToLower(strings.TrimSpace(v[idx+1:]))
		if name == "" {
			return nil, fmt.Errorf("--witness-pubkey value %q has empty name", v)
		}
		if seen[name] {
			return nil, fmt.Errorf("--witness-pubkey name %q repeated", name)
		}
		seen[name] = true
		b, err := hex.DecodeString(hexstr)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("--witness-pubkey %q pubkey must be 64 hex chars (32 bytes); got %q", name, hexstr)
		}
		out = append(out, WitnessKey{Name: name, Pubkey: ed25519.PublicKey(b)})
	}
	return out, nil
}

// WitnessResponse is one entry from the platform's
// details.witness_responses array, narrowed to the fields the
// verifier needs.
type WitnessResponse struct {
	Name             string
	Success          bool
	ChainHead        string // from the surrounding anchor event's details
	WitnessTimestamp string
	SignatureHex     string
	FailureReason    string
}

// WitnessVerifyResult summarises the verifier's findings.
type WitnessVerifyResult struct {
	// TotalAnchors = number of audit.chain.anchor events scanned.
	TotalAnchors int
	// TotalResponses = sum of witness_responses across all anchors.
	TotalResponses int
	// PerWitness counts, keyed by witness name. Includes only
	// witnesses for which the customer supplied a pubkey.
	PerWitness map[string]*WitnessPerName
	// Anchors whose chain_head_at_anchor never appeared during the
	// chain walk — strongest tamper signal, equivalent to the
	// ChainHeadNotInWalk failure mode in signed_anchors.go.
	ChainHeadNotInWalk []string
}

type WitnessPerName struct {
	Checked  int
	Verified int
	Failures []string
}

func (r *WitnessVerifyResult) HasAnyFailures() bool {
	if len(r.ChainHeadNotInWalk) > 0 {
		return true
	}
	for _, p := range r.PerWitness {
		if len(p.Failures) > 0 {
			return true
		}
	}
	return false
}

// ExtractAnchorWitnessResponses re-reads the NDJSON export and pulls
// out every (chain_head, witness_response) pair. Re-reading rather
// than threading the data through Verify keeps verify.go ignorant of
// witness semantics — Verify only cares about hash continuity.
func ExtractAnchorWitnessResponses(r io.Reader) ([]WitnessResponse, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	out := []WitnessResponse{}
	for {
		var ev struct {
			Action  string         `json:"action"`
			Details map[string]any `json:"details"`
		}
		if err := dec.Decode(&ev); err != nil {
			if err == io.EOF {
				break
			}
			// Skip malformed lines silently — verify.go is the
			// authoritative validator for line-level errors. Here we
			// only care about anchor events.
			continue
		}
		if ev.Action != "audit.chain.anchor" {
			continue
		}
		head, _ := ev.Details["chain_head_at_anchor"].(string)
		raw, ok := ev.Details["witness_responses"]
		if !ok || head == "" {
			continue
		}
		arr, ok := raw.([]any)
		if !ok {
			continue
		}
		for _, item := range arr {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, WitnessResponse{
				Name:             stringField(m, "name"),
				Success:          boolField(m, "success"),
				ChainHead:        head,
				WitnessTimestamp: stringField(m, "witness_timestamp"),
				SignatureHex:     stringField(m, "signature_hex"),
				FailureReason:    stringField(m, "failure_reason"),
			})
		}
	}
	return out, nil
}

func stringField(m map[string]any, k string) string {
	v, _ := m[k].(string)
	return v
}

func boolField(m map[string]any, k string) bool {
	v, _ := m[k].(bool)
	return v
}

// VerifyWitnessSignatures checks every witness response against the
// matching customer-supplied pubkey. Witnesses without a configured
// pubkey are reported in TotalResponses but never verified — same
// philosophy as signed_anchors.go: "no key, no check, no opinion".
//
// walkedHeads is the set of every chain_head seen during the Verify()
// walk. A signed anchor whose chain_head isn't in this set proves the
// chain has been rewritten — even a self-consistent rewrite cannot
// restore a removed historical head without breaking continuity.
func VerifyWitnessSignatures(
	responses []WitnessResponse,
	keys []WitnessKey,
	walkedHeads map[string]bool,
) WitnessVerifyResult {
	keyByName := map[string]ed25519.PublicKey{}
	for _, k := range keys {
		keyByName[k.Name] = k.Pubkey
	}

	res := WitnessVerifyResult{
		TotalAnchors:   0,
		TotalResponses: 0,
		PerWitness:     map[string]*WitnessPerName{},
	}

	seenAnchors := map[string]bool{}
	for _, r := range responses {
		res.TotalResponses++

		// Count distinct chain heads as distinct anchors.
		if !seenAnchors[r.ChainHead] {
			seenAnchors[r.ChainHead] = true
			res.TotalAnchors++
			if walkedHeads != nil && !walkedHeads[strings.ToLower(r.ChainHead)] {
				res.ChainHeadNotInWalk = append(res.ChainHeadNotInWalk,
					fmt.Sprintf("anchor head %s never appeared during the chain walk",
						r.ChainHead))
			}
		}

		pk, hasKey := keyByName[r.Name]
		if !hasKey {
			continue
		}
		entry := res.PerWitness[r.Name]
		if entry == nil {
			entry = &WitnessPerName{}
			res.PerWitness[r.Name] = entry
		}
		entry.Checked++

		if !r.Success {
			entry.Failures = append(entry.Failures,
				fmt.Sprintf("%s: platform recorded failure (%s) for anchor head %s",
					r.Name, r.FailureReason, r.ChainHead))
			continue
		}
		if r.SignatureHex == "" {
			entry.Failures = append(entry.Failures,
				fmt.Sprintf("%s: no signature_hex on anchor head %s", r.Name, r.ChainHead))
			continue
		}
		sig, err := hex.DecodeString(r.SignatureHex)
		if err != nil || len(sig) != ed25519.SignatureSize {
			entry.Failures = append(entry.Failures,
				fmt.Sprintf("%s: malformed signature on anchor head %s", r.Name, r.ChainHead))
			continue
		}
		headBytes, err := hex.DecodeString(r.ChainHead)
		if err != nil || len(headBytes) != 32 {
			entry.Failures = append(entry.Failures,
				fmt.Sprintf("%s: malformed chain_head on anchor %s", r.Name, r.ChainHead))
			continue
		}
		msg := append(headBytes, []byte(r.WitnessTimestamp)...)
		if !ed25519.Verify(pk, msg, sig) {
			entry.Failures = append(entry.Failures,
				fmt.Sprintf("%s: signature INVALID on anchor head %s (witness_timestamp=%s)",
					r.Name, r.ChainHead, r.WitnessTimestamp))
			continue
		}
		entry.Verified++
	}

	// Stable output order for deterministic CLI exit-text.
	sort.Strings(res.ChainHeadNotInWalk)
	return res
}
