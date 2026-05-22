package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// SignedAnchor is a single (chain_head, signature) pair from the
// customer-side archive. The customer's signer reads the chain_head
// from an `audit.chain.anchor` webhook event, verifies the platform's
// fingerprint matches the locally-configured key, and signs the raw
// 32 bytes of the chain head with Ed25519. The signed pair is then
// stored in the customer's archive (SIEM, append-only file, etc.).
type SignedAnchor struct {
	LineNo       int
	ChainHeadHex string
	SignatureHex string
}

// ParseSignedAnchors reads a text file with one signed anchor per
// line. Format:
//
//	<chain_head_hex>  <signature_hex>
//
// where chain_head_hex is exactly 64 lowercase hex chars (32 raw bytes)
// and signature_hex is exactly 128 lowercase hex chars (64 raw bytes
// for an Ed25519 signature). Blank lines and lines beginning with '#'
// are ignored.
//
// Parse failures are returned with the line number so the operator can
// fix the archive file. We do NOT verify signatures here — that's
// VerifySignedAnchors's job (it needs the customer's pubkey + the set
// of chain heads reached during the walk).
func ParseSignedAnchors(r io.Reader) ([]SignedAnchor, error) {
	var out []SignedAnchor
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("line %d: expected 2 whitespace-separated fields, got %d", lineNo, len(fields))
		}
		head := strings.ToLower(fields[0])
		sig := strings.ToLower(fields[1])
		if len(head) != 64 {
			return nil, fmt.Errorf("line %d: chain_head must be 64 hex chars (32 bytes), got %d", lineNo, len(head))
		}
		if len(sig) != 128 {
			return nil, fmt.Errorf("line %d: signature must be 128 hex chars (64 bytes), got %d", lineNo, len(sig))
		}
		if _, err := hex.DecodeString(head); err != nil {
			return nil, fmt.Errorf("line %d: chain_head is not valid hex: %v", lineNo, err)
		}
		if _, err := hex.DecodeString(sig); err != nil {
			return nil, fmt.Errorf("line %d: signature is not valid hex: %v", lineNo, err)
		}
		out = append(out, SignedAnchor{
			LineNo:       lineNo,
			ChainHeadHex: head,
			SignatureHex: sig,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// VerifySignedAnchorsResult summarises the outcome of checking every
// signed anchor against (a) the customer's pubkey and (b) the set of
// chain heads reached during the chain walk.
type VerifySignedAnchorsResult struct {
	TotalAnchors          int
	SignatureFailures     []string // human-readable failure descriptions
	ChainHeadNotInWalk    []string // anchor head not seen during chain walk
}

// HasAnyFailures returns true if there were any verification failures
// of any kind. Callers exit non-zero in that case.
func (r VerifySignedAnchorsResult) HasAnyFailures() bool {
	return len(r.SignatureFailures) > 0 || len(r.ChainHeadNotInWalk) > 0
}

// VerifySignedAnchors checks each anchor in two independent ways:
//
//  1. Ed25519 signature validates against the customer's pubkey over
//     the raw 32 bytes of the anchor's chain head. This proves the
//     signature was produced by the holder of the customer's private
//     key — a platform-side attacker cannot forge it without that key.
//
//  2. The signed chain head appeared somewhere in the chain walk of
//     the supplied NDJSON input. If a signed anchor references a head
//     that's NOT in the recomputed walk, the chain has been rewritten
//     since the anchor was signed — the attacker's rewritten chain
//     can be self-consistent but cannot reproduce the historical head
//     the customer already signed.
//
// pubkey must be the 32-byte raw Ed25519 public key.
// walkedHeads must contain every chain_head reached during the walk
// (including the final head) — as a hex-keyed set.
func VerifySignedAnchors(
	anchors []SignedAnchor,
	pubkey ed25519.PublicKey,
	walkedHeads map[string]bool,
) VerifySignedAnchorsResult {
	res := VerifySignedAnchorsResult{TotalAnchors: len(anchors)}
	for _, a := range anchors {
		headBytes, _ := hex.DecodeString(a.ChainHeadHex)
		sigBytes, _ := hex.DecodeString(a.SignatureHex)
		if !ed25519.Verify(pubkey, headBytes, sigBytes) {
			res.SignatureFailures = append(res.SignatureFailures,
				fmt.Sprintf("line %d: signature does not verify against customer pubkey", a.LineNo))
			continue
		}
		// Signature is valid. Now check the chain head is one we
		// actually reached during the walk.
		if !walkedHeads[a.ChainHeadHex] {
			res.ChainHeadNotInWalk = append(res.ChainHeadNotInWalk,
				fmt.Sprintf("line %d: signed chain_head %s... NOT FOUND in input chain — chain rewritten since this anchor was signed",
					a.LineNo, a.ChainHeadHex[:16]))
		}
	}
	return res
}
