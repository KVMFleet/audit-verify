# kvmfleet-verify

Offline verifier for the KVM Fleet audit chain.

`kvmfleet-verify` re-walks the SHA-256 hash chain over an NDJSON export
of your audit events and reports whether the chain is intact — without
needing network access to the KVM Fleet platform. If we go offline,
disappear, or you simply want to prove tamper-evidence on your own
machine for a compliance auditor, this is the tool.

## How to use

1. **Export your audit log.** In the dashboard, open Audit → Export →
   NDJSON. You get a file like `kvmfleet-audit-20260514-143000.ndjson`,
   one event per line.

2. **(Optional) Note your chain anchor.** On the Compliance page, find
   the "Audit chain anchor" value (a 64-char hex string). For most orgs
   this is 64 zeros — the only time it differs is after a retention
   sweep, when it advances to the last-deleted row's hash.

3. **Run the verifier:**

   ```bash
   kvmfleet-verify --input kvmfleet-audit-20260514-143000.ndjson
   # or, with a non-default anchor:
   kvmfleet-verify --input audit.ndjson --anchor 1a2b...64hex
   # or pipe:
   cat audit.ndjson | kvmfleet-verify
   ```

   On success:
   ```
   OK 663 event(s)
   chain head: a1b2c3...
   ```

   On break (tampering, deletion, or reordering detected):
   ```
   BREAK: row_hash mismatch at id=433 (expected ..., got ...)
   checked 433 event(s) before break
   ```
   Exit code 1 on break; 0 on success.

## What the verifier proves

A successful run proves that **every event in your export was hashed
with the data shown**, anchored to the (optional) starting hash, and
that nobody has altered any field — `action`, `actor`, `target`,
`details`, timestamps, all of it — without breaking the chain.

A failed run pinpoints the first event whose hash doesn't match its
content or whose `prev_hash` doesn't match the prior row.

## What it does NOT prove

- That the platform recorded **every** action it should have. The
  verifier checks integrity of what's in the export, not completeness.
  An attacker with database-superuser access *and* the ability to
  silently re-hash subsequent rows could in theory truncate the tail
  — though they'd have to do so before any external party (you,
  another verifier copy, your SIEM via the audit-webhook stream)
  captured a snapshot. Tamper-evidence is only as strong as the
  freshness of your last external attestation.
- That a forward-looking event hasn't yet been added; the verifier
  walks what you give it.

The "customer-owned audit signing keys" feature on the KVM Fleet
roadmap (Phase 3, trigger-driven) closes the residual gap by signing
every event with a key the platform doesn't hold.

## Build

The build runs entirely inside a pinned `golang:1.24-alpine` image —
no host Go toolchain needed:

```bash
make build       # cross-compiles for linux/macOS/windows × amd64/arm64
make test        # runs go test in the same container
```

Reproducibility is enforced via the pinned image digest, `-trimpath`,
and `-buildvcs=false`. Two machines building the same source tree
with the same `VERSION` produce byte-identical binaries — the
foundation for `cosign`-signed releases (see `kvmfleet/TODO.md`,
"Reproducible builds + signed agent binaries").

## License

Business Source License 1.1 (`LICENSE`). Source-available; free for
audit + self-verification use; commercial redistribution requires a
licence from KVM Fleet. Auto-converts to Apache 2.0 four years after
each release.

## Verifying the hash algorithm

The verifier mirrors the platform's [`audit.record()`][svc] hashing
exactly:

```
row_hash = SHA-256(prev_hash || canonical_json(payload))
```

where `canonical_json` is `json.dumps(payload, sort_keys=True,
separators=(",", ":"), default=str)` with Python's `ensure_ascii=True`
default. The Go side's `canonical.go` replicates this byte-for-byte
(sorted keys, `\uXXXX` for any rune ≥ 0x80, no HTML escaping). Test
fixtures in `canonical_test.go` lock those bytes against drift.

[svc]: https://github.com/KVMFleet/platform/blob/main/app/services/audit.py
