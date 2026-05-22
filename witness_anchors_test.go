package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseWitnessKeyFlag_HappyPath(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	out, err := ParseWitnessKeyFlag([]string{"primary:" + hex.EncodeToString(pub)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 || out[0].Name != "primary" {
		t.Fatalf("expected one parsed key named 'primary', got %+v", out)
	}
}

func TestParseWitnessKeyFlag_BadFormat(t *testing.T) {
	cases := []string{
		"noname",                        // no colon
		":hexonly",                      // empty name
		"name:",                         // empty hex
		"name:nothex" + strings.Repeat("z", 58), // bad hex
		"name:abcd",                     // too short
	}
	for _, c := range cases {
		_, err := ParseWitnessKeyFlag([]string{c})
		if err == nil {
			t.Errorf("expected error for input %q, got nil", c)
		}
	}
}

func TestParseWitnessKeyFlag_DuplicateName(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h := hex.EncodeToString(pub)
	_, err := ParseWitnessKeyFlag([]string{"a:" + h, "a:" + h})
	if err == nil {
		t.Fatalf("expected duplicate-name error")
	}
}

func TestVerifyWitnessSignatures_HappyPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	chainHead := strings.Repeat("ab", 32)
	headBytes, _ := hex.DecodeString(chainHead)
	ts := "2026-05-22T12:00:00+00:00"
	sig := ed25519.Sign(priv, append(headBytes, []byte(ts)...))

	responses := []WitnessResponse{{
		Name: "primary", Success: true, ChainHead: chainHead,
		WitnessTimestamp: ts, SignatureHex: hex.EncodeToString(sig),
	}}
	walked := map[string]bool{chainHead: true}
	res := VerifyWitnessSignatures(responses,
		[]WitnessKey{{Name: "primary", Pubkey: pub}}, walked)

	if res.HasAnyFailures() {
		t.Fatalf("expected no failures, got %+v", res)
	}
	if res.PerWitness["primary"].Verified != 1 {
		t.Fatalf("expected 1 verified, got %+v", res.PerWitness["primary"])
	}
}

func TestVerifyWitnessSignatures_WrongPubkey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	chainHead := strings.Repeat("cd", 32)
	headBytes, _ := hex.DecodeString(chainHead)
	ts := "2026-05-22T12:00:00+00:00"
	sig := ed25519.Sign(priv, append(headBytes, []byte(ts)...))

	responses := []WitnessResponse{{
		Name: "primary", Success: true, ChainHead: chainHead,
		WitnessTimestamp: ts, SignatureHex: hex.EncodeToString(sig),
	}}
	walked := map[string]bool{chainHead: true}
	res := VerifyWitnessSignatures(responses,
		[]WitnessKey{{Name: "primary", Pubkey: otherPub}}, walked)
	if !res.HasAnyFailures() {
		t.Fatalf("expected failure for wrong pubkey")
	}
}

func TestVerifyWitnessSignatures_ChainHeadNotInWalk(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	chainHead := strings.Repeat("ef", 32)
	headBytes, _ := hex.DecodeString(chainHead)
	ts := "2026-05-22T12:00:00+00:00"
	sig := ed25519.Sign(priv, append(headBytes, []byte(ts)...))

	responses := []WitnessResponse{{
		Name: "primary", Success: true, ChainHead: chainHead,
		WitnessTimestamp: ts, SignatureHex: hex.EncodeToString(sig),
	}}
	// The signature itself is valid, but the chain head was never
	// reached during the walk → tamper-evident.
	walked := map[string]bool{} // empty
	res := VerifyWitnessSignatures(responses,
		[]WitnessKey{{Name: "primary", Pubkey: pub}}, walked)
	if len(res.ChainHeadNotInWalk) == 0 {
		t.Fatalf("expected ChainHeadNotInWalk failure")
	}
}

func TestVerifyWitnessSignatures_PlatformRecordedFailure(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	chainHead := strings.Repeat("11", 32)
	responses := []WitnessResponse{{
		Name: "primary", Success: false, ChainHead: chainHead,
		FailureReason: "timeout",
	}}
	walked := map[string]bool{chainHead: true}
	res := VerifyWitnessSignatures(responses,
		[]WitnessKey{{Name: "primary", Pubkey: pub}}, walked)
	if !res.HasAnyFailures() {
		t.Fatalf("expected platform-recorded failure to bubble up")
	}
}

func TestVerifyWitnessSignatures_NoKeyMeansNoCheck(t *testing.T) {
	chainHead := strings.Repeat("22", 32)
	// Response from a witness the customer didn't supply a key for —
	// counted but not verified, never a failure.
	responses := []WitnessResponse{{
		Name: "stranger", Success: true, ChainHead: chainHead,
		WitnessTimestamp: "t", SignatureHex: "ff",
	}}
	walked := map[string]bool{chainHead: true}
	res := VerifyWitnessSignatures(responses, nil, walked)
	if res.HasAnyFailures() {
		t.Fatalf("expected no failures when no key supplied; got %+v", res)
	}
	if res.TotalResponses != 1 || res.TotalAnchors != 1 {
		t.Fatalf("expected response/anchor counts to be 1; got %+v", res)
	}
}

func TestExtractAnchorWitnessResponses_IgnoresNonAnchorEvents(t *testing.T) {
	// Build a tiny NDJSON: one non-anchor event, one anchor event with
	// a witness_responses array.
	ndjson := `{"action":"login.success","details":{"foo":"bar"}}
{"action":"audit.chain.anchor","details":{"chain_head_at_anchor":"aa","witness_responses":[{"name":"w","success":true,"witness_timestamp":"t","signature_hex":"ff"}]}}
`
	out, err := ExtractAnchorWitnessResponses(strings.NewReader(ndjson))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(out) != 1 || out[0].Name != "w" || out[0].ChainHead != "aa" {
		t.Fatalf("unexpected output: %+v", out)
	}
}
