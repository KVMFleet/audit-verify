package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	return pub, priv
}

func signHead(priv ed25519.PrivateKey, headHex string) string {
	headBytes, _ := hex.DecodeString(headHex)
	sig := ed25519.Sign(priv, headBytes)
	return hex.EncodeToString(sig)
}

// --- ParseSignedAnchors -----------------------------------------------------

func TestParseSignedAnchors_HappyPath(t *testing.T) {
	pub, priv := mustKeypair(t)
	_ = pub
	head1 := strings.Repeat("a", 64)
	head2 := strings.Repeat("b", 64)
	body := strings.Join([]string{
		"# this is a comment",
		"",
		head1 + "  " + signHead(priv, head1),
		head2 + "  " + signHead(priv, head2),
	}, "\n")
	got, err := ParseSignedAnchors(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 anchors, got %d", len(got))
	}
	if got[0].ChainHeadHex != head1 || got[1].ChainHeadHex != head2 {
		t.Errorf("chain heads not preserved")
	}
}

func TestParseSignedAnchors_RejectsBadHexLength(t *testing.T) {
	_, err := ParseSignedAnchors(strings.NewReader("abcd  ef\n"))
	if err == nil {
		t.Fatal("expected error on short hex; got nil")
	}
}

func TestParseSignedAnchors_RejectsNonHex(t *testing.T) {
	head := strings.Repeat("g", 64) // 'g' is not a hex char
	sig := strings.Repeat("a", 128)
	_, err := ParseSignedAnchors(strings.NewReader(head + "  " + sig + "\n"))
	if err == nil {
		t.Fatal("expected error on non-hex; got nil")
	}
}

func TestParseSignedAnchors_TolerantOfBlankLinesAndComments(t *testing.T) {
	pub, priv := mustKeypair(t)
	_ = pub
	head := strings.Repeat("c", 64)
	body := "\n\n# leading comment\n  \n" +
		head + "  " + signHead(priv, head) + "\n" +
		"# trailing comment\n"
	got, err := ParseSignedAnchors(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 anchor, got %d", len(got))
	}
}

// --- VerifySignedAnchors ----------------------------------------------------

func TestVerifySignedAnchors_HappyPath(t *testing.T) {
	pub, priv := mustKeypair(t)
	head := strings.Repeat("a", 64)
	walked := map[string]bool{head: true}
	anchors := []SignedAnchor{{LineNo: 1, ChainHeadHex: head, SignatureHex: signHead(priv, head)}}
	res := VerifySignedAnchors(anchors, pub, walked)
	if res.HasAnyFailures() {
		t.Fatalf("expected clean result, got: %+v", res)
	}
	if res.TotalAnchors != 1 {
		t.Errorf("expected TotalAnchors=1, got %d", res.TotalAnchors)
	}
}

func TestVerifySignedAnchors_BadSignatureRejected(t *testing.T) {
	pub, _ := mustKeypair(t)
	head := strings.Repeat("a", 64)
	walked := map[string]bool{head: true}
	// Use a signature that wasn't produced by `priv`.
	wrongSig := strings.Repeat("11", 64)
	anchors := []SignedAnchor{{LineNo: 1, ChainHeadHex: head, SignatureHex: wrongSig}}
	res := VerifySignedAnchors(anchors, pub, walked)
	if !res.HasAnyFailures() {
		t.Fatal("expected signature failure")
	}
	if len(res.SignatureFailures) != 1 {
		t.Errorf("expected 1 signature failure, got %d", len(res.SignatureFailures))
	}
}

func TestVerifySignedAnchors_DetectsChainRewriteByMissingHead(t *testing.T) {
	pub, priv := mustKeypair(t)
	head := strings.Repeat("a", 64)
	// Signature is VALID, but the chain head was not reached in the
	// walk — that's the platform-side-rewrite signal we want to catch.
	walked := map[string]bool{strings.Repeat("b", 64): true}
	anchors := []SignedAnchor{{LineNo: 1, ChainHeadHex: head, SignatureHex: signHead(priv, head)}}
	res := VerifySignedAnchors(anchors, pub, walked)
	if !res.HasAnyFailures() {
		t.Fatal("expected chain-rewrite detection")
	}
	if len(res.ChainHeadNotInWalk) != 1 {
		t.Errorf("expected 1 chain-head-not-in-walk failure, got %d", len(res.ChainHeadNotInWalk))
	}
	if len(res.SignatureFailures) != 0 {
		t.Errorf("did not expect signature failures, got %d", len(res.SignatureFailures))
	}
}

func TestVerifySignedAnchors_WrongPubkeyRejected(t *testing.T) {
	_, priv := mustKeypair(t)         // signing key
	otherPub, _ := mustKeypair(t)     // verifier holds DIFFERENT pubkey
	head := strings.Repeat("a", 64)
	walked := map[string]bool{head: true}
	anchors := []SignedAnchor{{LineNo: 1, ChainHeadHex: head, SignatureHex: signHead(priv, head)}}
	res := VerifySignedAnchors(anchors, otherPub, walked)
	if !res.HasAnyFailures() {
		t.Fatal("expected failure when pubkey doesn't match signing key")
	}
	if len(res.SignatureFailures) != 1 {
		t.Errorf("expected 1 sig failure, got %d", len(res.SignatureFailures))
	}
}
