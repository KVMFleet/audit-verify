//go:build js && wasm

// WebAssembly entry point for the in-browser /security demo (#379).
//
// Exposes the same chain verifier the CLI uses (Verify) to JavaScript as a
// global function `kvmfleetVerify(ndjson, anchorHex)`. The verification runs
// entirely in the visitor's browser — nothing is uploaded — which is the
// whole point of the "don't trust us, verify it yourself" demo. Build with:
//
//	GOOS=js GOARCH=wasm go build -o kvmfleet-verify.wasm .
//
// Reuses the shared core (Verify, canonical, …) verbatim, so the in-browser
// result is byte-identical to the offline CLI.
package main

import (
	"encoding/hex"
	"strings"
	"syscall/js"
)

// verifyJS is the JS-callable bridge:
//
//	kvmfleetVerify(ndjson: string, anchorHex?: string)
//	  -> { ok: bool, checked: number, first_break_id: number,
//	       message: string, chain_head: string }
//
// anchorHex is optional; empty / omitted means the all-zero anchor (a
// brand-new org or one that's never had a retention sweep).
func verifyJS(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return map[string]any{"ok": false, "checked": 0, "message": "no input provided"}
	}
	ndjson := args[0].String()

	var anchor [32]byte
	if len(args) >= 2 {
		h := strings.TrimSpace(args[1].String())
		if h != "" {
			b, err := hex.DecodeString(h)
			if err != nil || len(b) != 32 {
				return map[string]any{
					"ok": false, "checked": 0,
					"message": "anchor must be 32-byte hex (64 characters)",
				}
			}
			copy(anchor[:], b)
		}
	}

	res, err := Verify(strings.NewReader(ndjson), anchor)
	if err != nil {
		return map[string]any{"ok": false, "checked": res.Checked, "message": err.Error()}
	}
	return map[string]any{
		"ok":             res.OK,
		"checked":        res.Checked,
		"first_break_id": float64(res.FirstBreakID),
		"message":        res.Message,
		"chain_head":     res.ChainHead,
	}
}

func main() {
	js.Global().Set("kvmfleetVerify", js.FuncOf(verifyJS))
	js.Global().Get("console").Call("log", "kvmfleet-verify (wasm) ready")
	select {} // keep the instance alive for the page's lifetime
}
