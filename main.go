// kvmfleet-verify — offline verifier for the KVM Fleet audit chain.
//
// Walks an NDJSON export of audit events from `/v1/audit/events.ndjson`
// and recomputes the SHA-256 hash chain row-by-row. Detects tampering,
// reordering, or deletion of audit events without requiring network
// access to the platform.
//
// Usage:
//
//	kvmfleet-verify --input audit.ndjson [--anchor <hex>] [--quiet]
//	cat audit.ndjson | kvmfleet-verify [--anchor <hex>]
//
// External-witness mode (catches a platform-side rewrite):
//
//	# Use a chain head you archived from your SIEM (the platform periodically
//	# publishes `audit.chain.anchor` events; your SIEM stores them out-of-band).
//	kvmfleet-verify --input audit.ndjson --check-against-anchor <hex>
//
// Exit code: 0 on a verified chain; 1 on break, anchor mismatch,
// malformed input, or missing flags.
//
// License: Business Source License 1.1. See LICENSE.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const version = "0.2.0-dev"

func main() {
	var (
		input       string
		anchorHex   string
		expectedHex string
		quiet       bool
		showVer     bool
	)
	flag.StringVar(&input, "input", "", "Path to NDJSON export (default: stdin)")
	flag.StringVar(&anchorHex, "anchor", "", "Org's audit_chain_anchor as 64 hex chars (default: 64 zeros)")
	flag.StringVar(&expectedHex, "check-against-anchor", "",
		"Expected chain head after processing all input — typically the\n"+
			"\tchain_head_at_anchor from an `audit.chain.anchor` event your SIEM\n"+
			"\tarchived. Mismatch means the chain has been rewritten since the\n"+
			"\tanchor was published; the verifier exits non-zero.")
	flag.BoolVar(&quiet, "quiet", false, "Suppress success output; only print on failure")
	flag.BoolVar(&showVer, "version", false, "Print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "kvmfleet-verify %s — offline KVM Fleet audit-chain verifier\n", version)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  kvmfleet-verify --input audit.ndjson [--anchor <hex>] [--check-against-anchor <hex>]")
		fmt.Fprintln(os.Stderr, "  cat audit.ndjson | kvmfleet-verify [--anchor <hex>]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Flags:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Export the NDJSON from your dashboard: Audit → Export → NDJSON.")
		fmt.Fprintln(os.Stderr, "The anchor is shown on the Compliance page (default 64 zeros for")
		fmt.Fprintln(os.Stderr, "any org that has never had an audit retention sweep).")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "--check-against-anchor takes a chain_head_at_anchor value from a previous")
		fmt.Fprintln(os.Stderr, "`audit.chain.anchor` event. Use a value your SIEM archived OUT-OF-BAND from")
		fmt.Fprintln(os.Stderr, "the platform — that's what makes this externally-witnessed integrity check.")
	}
	flag.Parse()

	if showVer {
		fmt.Println(version)
		return
	}

	var anchor [32]byte
	if anchorHex != "" {
		b, err := hex.DecodeString(anchorHex)
		if err != nil || len(b) != 32 {
			fmt.Fprintf(os.Stderr, "kvmfleet-verify: --anchor must be exactly 64 hex chars (32 bytes); got %q\n", anchorHex)
			os.Exit(1)
		}
		copy(anchor[:], b)
	}

	// Normalise the expected anchor hex up-front so we fail fast on a typo.
	if expectedHex != "" {
		expectedHex = strings.ToLower(strings.TrimSpace(expectedHex))
		if b, err := hex.DecodeString(expectedHex); err != nil || len(b) != 32 {
			fmt.Fprintf(os.Stderr, "kvmfleet-verify: --check-against-anchor must be exactly 64 hex chars (32 bytes); got %q\n", expectedHex)
			os.Exit(1)
		}
	}

	var r io.Reader = os.Stdin
	if input != "" {
		f, err := os.Open(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "kvmfleet-verify: open %s: %v\n", input, err)
			os.Exit(1)
		}
		defer f.Close()
		r = f
	}

	res, err := Verify(r, anchor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kvmfleet-verify: %v\n", err)
		os.Exit(1)
	}

	if !res.OK {
		fmt.Fprintf(os.Stderr, "BREAK: %s\n", res.Message)
		fmt.Fprintf(os.Stderr, "checked %d event(s) before break\n", res.Checked)
		os.Exit(1)
	}

	// External-witness check. The chain itself verified — but does the
	// final head match the value the customer archived from their SIEM?
	// A platform-side attacker can rewrite the chain to a self-consistent
	// state, but they cannot reach into the customer's archived
	// chain.anchor payloads. Mismatch here = tamper detected externally.
	if expectedHex != "" {
		actual := strings.ToLower(res.ChainHead)
		if actual != expectedHex {
			fmt.Fprintln(os.Stderr, "TAMPER DETECTED: chain head does not match the archived anchor.")
			fmt.Fprintf(os.Stderr, "  expected (from anchor): %s\n", expectedHex)
			fmt.Fprintf(os.Stderr, "  computed (from input):  %s\n", actual)
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Possible causes:")
			fmt.Fprintln(os.Stderr, "  - The audit chain has been rewritten since the anchor was published")
			fmt.Fprintln(os.Stderr, "    (escalate to KVM Fleet incident response + your own auditor).")
			fmt.Fprintln(os.Stderr, "  - The NDJSON export covers a different period than the anchor.")
			fmt.Fprintln(os.Stderr, "  - The anchor value was mis-copied (re-fetch from SIEM).")
			os.Exit(1)
		}
		if !quiet {
			fmt.Printf("OK %d event(s)\n", res.Checked)
			fmt.Printf("chain head: %s\n", res.ChainHead)
			fmt.Println("anchor matches: VERIFIED")
		}
		return
	}

	if !quiet {
		fmt.Printf("OK %d event(s)\n", res.Checked)
		if res.ChainHead != "" {
			fmt.Printf("chain head: %s\n", res.ChainHead)
		}
	}
}
