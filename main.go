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
// Exit code: 0 on a verified chain; 1 on break, malformed input, or
// missing flags.
//
// License: Business Source License 1.1. See LICENSE.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
)

const version = "0.1.0-dev"

func main() {
	var (
		input     string
		anchorHex string
		quiet     bool
		showVer   bool
	)
	flag.StringVar(&input, "input", "", "Path to NDJSON export (default: stdin)")
	flag.StringVar(&anchorHex, "anchor", "", "Org's audit_chain_anchor as 64 hex chars (default: 64 zeros)")
	flag.BoolVar(&quiet, "quiet", false, "Suppress success output; only print on failure")
	flag.BoolVar(&showVer, "version", false, "Print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "kvmfleet-verify %s — offline KVM Fleet audit-chain verifier\n", version)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  kvmfleet-verify --input audit.ndjson [--anchor <hex>] [--quiet]")
		fmt.Fprintln(os.Stderr, "  cat audit.ndjson | kvmfleet-verify [--anchor <hex>]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Flags:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Export the NDJSON from your dashboard: Audit → Export → NDJSON.")
		fmt.Fprintln(os.Stderr, "The anchor is shown on the Compliance page (default 64 zeros for")
		fmt.Fprintln(os.Stderr, "any org that has never had an audit retention sweep).")
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

	if !quiet {
		fmt.Printf("OK %d event(s)\n", res.Checked)
		if res.ChainHead != "" {
			fmt.Printf("chain head: %s\n", res.ChainHead)
		}
	}
}
