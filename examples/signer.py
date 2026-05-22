#!/usr/bin/env python3
"""Reference customer-side signer for KVM Fleet audit-chain anchors.

PRIVATE-KEY SAFETY — read before deploying.

This script holds the Ed25519 PRIVATE key that signs your audit-chain
anchors. The KVM Fleet platform never sees this key. That is the
entire point: even if the platform is fully compromised, the attacker
cannot forge new signed anchors because they don't have your private
key.

That means:
  1. Generate the keypair on a machine YOU control, NOT on the platform.
  2. Upload only the PUBLIC half to KVM Fleet (Compliance → Audit-chain
     signing key).
  3. Keep the PRIVATE key on the machine this script runs on (or in a
     secrets manager / HSM that this script reads from). Treat it
     as you would a TLS server private key.
  4. Back up the private key out-of-band. Losing it loses the ability
     to verify historical signatures.

# Deployment options

This script is intentionally small (~80 lines). Three common ways to
wire it up; pick whichever fits your existing infra:

OPTION A — webhook receiver (synchronous)
    Run a tiny Flask/FastAPI/anything-HTTP receiver on infrastructure
    YOU control. Point a KVM Fleet audit webhook at it. Verify the
    HMAC signature on incoming webhooks first (platform secret —
    different from this script's private key). On each
    `audit.chain.anchor` event, this script reads the chain_head,
    verifies the platform's fingerprint matches what you expect,
    then signs and appends to your archive.

OPTION B — batch via SIEM (asynchronous)
    Your SIEM (Splunk / Datadog / ELK) ingests all KVM Fleet audit
    events via the audit-webhook stream. A scheduled job (cron,
    Airflow, whatever) reads the most-recent audit.chain.anchor
    events from the SIEM and pipes their payloads into this script.
    Lower-pressure than option A; tolerates webhook delivery delays.

OPTION C — manual ad-hoc
    For demos or testing — paste a webhook payload into stdin, see
    the signed line on stdout, copy to a file.

# Usage

    # generate a keypair (do this ONCE, on a machine you control)
    python signer.py --gen-key > kvmfleet-audit.key
    chmod 0600 kvmfleet-audit.key
    python signer.py --gen-key --pubkey-only --from kvmfleet-audit.key
    # → upload the printed 64-hex public key to KVM Fleet Compliance page

    # sign a payload (the entire JSON body of one audit.chain.anchor webhook)
    cat anchor-payload.json | python signer.py --sign --key kvmfleet-audit.key \\
        --expected-fingerprint <your-fingerprint-from-compliance-page> \\
        >> signed-anchors.txt

# Output format (one line per signed anchor):
#   <chain_head_hex>  <signature_hex>
# 64 hex chars (chain head) + two spaces + 128 hex chars (signature).
# This is exactly what `kvmfleet-verify --signed-anchors <file>` expects.

# Requires PyNaCl: `pip install pynacl`

License: BSL-1.1 (same as the audit-verify repo). Use freely;
redistribute under a commercial product requires a license from
KVM Fleet.
"""
import argparse
import hashlib
import json
import sys

try:
    from nacl.signing import SigningKey, VerifyKey
except ImportError:
    sys.stderr.write("pynacl is required: pip install pynacl\n")
    sys.exit(2)


def gen_key(pubkey_only: bool, from_path: str | None) -> int:
    """Either generate a fresh keypair (writes private key to stdout, no
    --from supplied) or read --from a private-key file and print the
    derived public key."""
    if from_path:
        with open(from_path, "rb") as f:
            sk = SigningKey(f.read())
    else:
        sk = SigningKey.generate()
        if not pubkey_only:
            sys.stdout.buffer.write(bytes(sk))
            return 0
    vk = sk.verify_key
    pub_hex = bytes(vk).hex()
    fp = hashlib.sha256(bytes(vk)).hexdigest()
    sys.stdout.write(f"{pub_hex}\n")
    sys.stderr.write(f"# fingerprint (sha256 of public key): {fp}\n")
    sys.stderr.write("# Upload the above 64-hex value to KVM Fleet Compliance → Audit-chain signing key.\n")
    return 0


def sign_payload(key_path: str, expected_fingerprint: str | None) -> int:
    """Read a webhook payload from stdin, verify it's an
    audit.chain.anchor event, optionally verify the platform's
    customer_pubkey_fingerprint matches ours, then sign + emit
    `<chain_head_hex>  <signature_hex>` on stdout."""
    with open(key_path, "rb") as f:
        sk = SigningKey(f.read())
    our_fp = hashlib.sha256(bytes(sk.verify_key)).hexdigest()

    payload = json.load(sys.stdin)
    action = payload.get("action")
    if action != "audit.chain.anchor":
        sys.stderr.write(f"# skipping non-anchor event: {action}\n")
        return 0

    details = payload.get("details") or {}
    head_hex = details.get("chain_head_at_anchor")
    if not head_hex:
        sys.stderr.write("# payload missing details.chain_head_at_anchor\n")
        return 1
    if not isinstance(head_hex, str) or len(head_hex) != 64:
        sys.stderr.write(f"# bad chain_head_at_anchor: {head_hex!r}\n")
        return 1

    # Sanity-check the platform's fingerprint matches OUR key — protects
    # against a hijacked webhook URL feeding us anchors for some other
    # org's chain that we'd then sign by mistake.
    platform_fp = details.get("customer_pubkey_fingerprint")
    if platform_fp is None:
        sys.stderr.write(
            "# platform did NOT include customer_pubkey_fingerprint — either signing "
            "was not enabled on this org, or the platform doesn't know about your key yet.\n"
        )
        return 1
    if expected_fingerprint and platform_fp != expected_fingerprint:
        sys.stderr.write(
            f"# fingerprint mismatch — refusing to sign.\n"
            f"#   platform says: {platform_fp}\n"
            f"#   we expect:     {expected_fingerprint}\n"
        )
        return 1
    if platform_fp != our_fp:
        sys.stderr.write(
            f"# platform fingerprint does not match our key — refusing to sign.\n"
            f"#   platform says: {platform_fp}\n"
            f"#   our key:       {our_fp}\n"
        )
        return 1

    head_bytes = bytes.fromhex(head_hex)
    sig = sk.sign(head_bytes).signature
    sys.stdout.write(f"{head_hex}  {sig.hex()}\n")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-key", help="Generate a keypair or derive the public key from an existing private key")
    g.add_argument("--pubkey-only", action="store_true", help="Print only the 64-hex public key (requires --from)")
    g.add_argument("--from", dest="from_path", help="Path to an existing private key file (skips generation)")

    s = sub.add_parser("sign", help="Sign an audit.chain.anchor webhook payload read from stdin")
    s.add_argument("--key", required=True, help="Path to the Ed25519 private key file (32 raw bytes)")
    s.add_argument(
        "--expected-fingerprint",
        help="The fingerprint shown on KVM Fleet Compliance page. If provided, signing refuses unless the platform's payload carries this exact value.",
    )

    # Allow shorthand: --gen-key + --sign without subcommands.
    # If a user runs `python signer.py --gen-key`, argparse will see no
    # subcommand. Handle that by translating top-level flags.
    if len(sys.argv) > 1 and sys.argv[1] in ("--gen-key", "--sign"):
        sys.argv[1] = sys.argv[1].lstrip("-")

    args = p.parse_args()
    if args.cmd == "gen-key":
        return gen_key(args.pubkey_only, args.from_path)
    if args.cmd == "sign":
        return sign_payload(args.key, args.expected_fingerprint)
    return 1


if __name__ == "__main__":
    sys.exit(main())
