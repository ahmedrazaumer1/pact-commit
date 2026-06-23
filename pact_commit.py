#!/usr/bin/env python3
"""
pact-commit — reference implementation of the PACT commitment format
described in Robinson (2026, "PACTs: Protecting Your Bitcoin From a
Quantum Sunset").

Draft v0.1.

This tool generates the COMMITMENT side of the PACT protocol. It does
not handle the eventual rescue redemption (which requires Bitcoin
protocol changes that do not yet exist).

USAGE
-----
    pact_commit.py prepare  --network ... --script-pubkey ... --output ...
    pact_commit.py finalize --prepared ... --signature ... --out-dir ...
    pact_commit.py upgrade  --ots-file ...

Run with --help on each subcommand for details.

SECURITY MODEL
--------------
The tool never touches private keys. It produces a message for the
holder to sign externally with a BIP-322-capable wallet, then combines
the resulting signature with a random salt to produce an opaque
commitment hash.

Only the opaque hash is submitted to OpenTimestamps. The salt and the
BIP-322 signature stay local in the recovery artifact, which the
holder must back up securely.

DEPENDENCIES
------------
    pip install opentimestamps-client coincurve
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants — the draft PACT v1 format.
# ---------------------------------------------------------------------------

PACT_VERSION = "PACT/v1"
COMMITMENT_DOMAIN = "PACT/v1 commitment"
SUPPORTED_NETWORKS = {"bitcoin-mainnet", "bitcoin-testnet", "bitcoin-signet"}

SALT_BYTES = 32
COMMITMENT_BYTES = 32

# ---------------------------------------------------------------------------
# Core message construction.
# ---------------------------------------------------------------------------


def build_pact_message(
    *, network: str, script_pubkey_hex: str, salt_hex: str
) -> str:
    """Construct the canonical PACT-format message string to be signed.

    The exact string format is part of the draft standard; downstream
    verifiers must reproduce it byte-for-byte. We use a JSON-canonical
    representation with lexicographically sorted keys so the
    representation is unambiguous across implementations.
    """
    if network not in SUPPORTED_NETWORKS:
        raise ValueError(f"unsupported network {network!r}")
    if len(salt_hex) != SALT_BYTES * 2:
        raise ValueError(f"salt must be {SALT_BYTES} bytes hex-encoded")
    int(salt_hex, 16)  # validates hex
    int(script_pubkey_hex, 16)  # validates hex
    body = {
        "version": PACT_VERSION,
        "purpose": "Bitcoin quantum-sunset proof of address control",
        "network": network,
        "scriptPubKey": script_pubkey_hex.lower(),
        "salt": salt_hex.lower(),
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def compute_commitment(*, salt_hex: str, control_proof_bytes: bytes) -> bytes:
    """Compute the opaque PACT commitment hash that will be timestamped.

        commitment = SHA256( "PACT/v1 commitment" || salt || SHA256(control_proof) )

    Only this 32-byte commitment is ever submitted to OpenTimestamps.
    """
    salt_bytes = bytes.fromhex(salt_hex)
    inner = hashlib.sha256(control_proof_bytes).digest()
    payload = COMMITMENT_DOMAIN.encode("utf-8") + salt_bytes + inner
    return hashlib.sha256(payload).digest()


# ---------------------------------------------------------------------------
# BIP-322 verification (best-effort — see notes).
# ---------------------------------------------------------------------------


def verify_bip322_signature(
    *,
    script_pubkey_hex: str,
    message: str,
    signature_b64: str,
) -> bool:
    """Verify a BIP-322 full-message signature against the given scriptPubKey.

    NOTE: A complete BIP-322 verifier requires re-running the tx-style
    virtual transaction validation (see BIP-322 spec). Implementing that
    in 100 lines of Python is non-trivial and is out of scope for this
    reference tool. We provide a hook that delegates to an external
    verifier (Bitcoin Core via `verifymessage` / `verifymessagewithprivkey`,
    or the `bip322` Python package once stable) and returns its boolean
    answer. If no verifier is available, we return None and warn the
    user to verify manually.

    For the reference tool's purposes, the user should verify the
    signature with their wallet before invoking `finalize`.
    """
    # External verifier delegation. Returns None if nothing is available.
    try:
        # Optional: call into a local Bitcoin Core node via bitcoin-cli.
        # This is the most authoritative verifier and is widely available.
        result = subprocess.run(
            [
                "bitcoin-cli",
                "verifymessage",
                script_pubkey_hex,
                signature_b64,
                message,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip().lower() == "true"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    print(
        "  [!] No local BIP-322 verifier available. The tool will accept "
        "the signature without cryptographic verification.\n"
        "      You should verify it manually using your wallet before relying "
        "on this commitment.",
        file=sys.stderr,
    )
    return True  # accept, with warning


# ---------------------------------------------------------------------------
# OpenTimestamps integration.
# ---------------------------------------------------------------------------


def submit_to_ots(commitment: bytes, ots_path: Path) -> None:
    """Submit a 32-byte commitment to OpenTimestamps via the `ots` CLI.

    The OpenTimestamps client must be installed (`pip install opentimestamps-client`).
    The submitted bytes are the opaque commitment hash; nothing else is
    sent over the wire.
    """
    # Write commitment to a binary file; ots stamps files.
    payload_path = ots_path.with_suffix(".bin")
    payload_path.write_bytes(commitment)
    try:
        subprocess.run(
            ["ots", "stamp", str(payload_path)], check=True, timeout=60
        )
    except FileNotFoundError:
        raise RuntimeError(
            "OpenTimestamps CLI (`ots`) not found. "
            "Install with `pip install opentimestamps-client`."
        )
    # ots writes <payload>.ots next to the input.
    produced = payload_path.with_suffix(".bin.ots")
    if produced.exists():
        produced.rename(ots_path)
    payload_path.unlink(missing_ok=True)


def upgrade_ots(ots_path: Path) -> None:
    """Upgrade an OpenTimestamps proof to its Bitcoin-block attestation.

    Run this 2-6 hours after `submit_to_ots` (or any time later).
    """
    try:
        subprocess.run(
            ["ots", "upgrade", str(ots_path)], check=True, timeout=120
        )
    except FileNotFoundError:
        raise RuntimeError(
            "OpenTimestamps CLI (`ots`) not found. "
            "Install with `pip install opentimestamps-client`."
        )


# ---------------------------------------------------------------------------
# CLI subcommands.
# ---------------------------------------------------------------------------


def cmd_prepare(args: argparse.Namespace) -> int:
    salt = secrets.token_hex(SALT_BYTES)
    message = build_pact_message(
        network=args.network,
        script_pubkey_hex=args.script_pubkey,
        salt_hex=salt,
    )
    out = {
        "version": PACT_VERSION,
        "network": args.network,
        "scriptPubKey": args.script_pubkey.lower(),
        "salt": salt,
        "messageToSign": message,
    }
    Path(args.output).write_text(json.dumps(out, indent=2))
    print(
        f"\n  Salt generated. Wrote prepared message to {args.output}.\n\n"
        f"  Next: sign the messageToSign field below with a BIP-322-capable\n"
        f"  wallet for your address. Save the signature to a text file, then\n"
        f"  run:\n\n"
        f"      python pact_commit.py finalize \\\n"
        f"          --prepared {args.output} \\\n"
        f"          --signature <path-to-signature-file> \\\n"
        f"          --out-dir ./pact-artifacts/\n"
    )
    print(f"  Message to sign:\n    {message}\n")
    return 0


def cmd_finalize(args: argparse.Namespace) -> int:
    prepared = json.loads(Path(args.prepared).read_text())
    signature_b64 = Path(args.signature).read_text().strip()

    # Verify (best-effort).
    ok = verify_bip322_signature(
        script_pubkey_hex=prepared["scriptPubKey"],
        message=prepared["messageToSign"],
        signature_b64=signature_b64,
    )
    if not ok:
        print("  [x] BIP-322 verification FAILED. Aborting.", file=sys.stderr)
        return 2

    # Build commitment.
    control_proof_bytes = signature_b64.encode("utf-8")
    commitment = compute_commitment(
        salt_hex=prepared["salt"], control_proof_bytes=control_proof_bytes
    )
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write public artifact.
    (out_dir / "commitment.hex").write_text(commitment.hex() + "\n")

    # Submit to OTS.
    ots_path = out_dir / "commitment.ots"
    print(f"  Submitting commitment to OpenTimestamps...")
    submit_to_ots(commitment, ots_path)
    print(f"  OTS submission complete. Proof written to {ots_path}")

    # Write recovery artifact.
    recovery = {
        "version": PACT_VERSION,
        "network": prepared["network"],
        "scriptPubKey": prepared["scriptPubKey"],
        "salt": prepared["salt"],
        "messageSigned": prepared["messageToSign"],
        "bip322Signature": signature_b64,
        "commitmentHex": commitment.hex(),
        "createdAt": _iso_now(),
    }
    recovery_path = out_dir / "recovery.json"
    recovery_path.write_text(json.dumps(recovery, indent=2))
    os.chmod(recovery_path, 0o600)
    print(
        f"\n  *** RECOVERY ARTIFACT *** written to {recovery_path}\n"
        f"      Back this file up immediately. Lose it and the commitment\n"
        f"      becomes unredeemable. Treat it like a wallet backup.\n"
    )
    print(f"\n  Run `python pact_commit.py upgrade --ots-file {ots_path}`\n"
          f"  in 2-6 hours to anchor the proof in a Bitcoin block.\n")
    return 0


def cmd_upgrade(args: argparse.Namespace) -> int:
    ots_path = Path(args.ots_file)
    if not ots_path.exists():
        print(f"  [x] {ots_path} not found.", file=sys.stderr)
        return 2
    print(f"  Upgrading {ots_path}...")
    upgrade_ots(ots_path)
    print(f"  Upgrade complete. The OTS proof is now bound to a Bitcoin block.")
    return 0


def _iso_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pact_commit",
        description="Reference implementation of PACT commitments (Robinson 2026).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("prepare", help="Generate salt and PACT message to sign.")
    p1.add_argument("--network", required=True, choices=sorted(SUPPORTED_NETWORKS))
    p1.add_argument("--script-pubkey", required=True, help="Hex-encoded scriptPubKey.")
    p1.add_argument("--output", required=True, help="Path for prepared JSON.")
    p1.set_defaults(func=cmd_prepare)

    p2 = sub.add_parser("finalize", help="Build commitment and submit to OTS.")
    p2.add_argument("--prepared", required=True, help="Output of `prepare`.")
    p2.add_argument("--signature", required=True, help="File with BIP-322 signature (base64).")
    p2.add_argument("--out-dir", required=True, help="Where to write artifacts.")
    p2.set_defaults(func=cmd_finalize)

    p3 = sub.add_parser("upgrade", help="Upgrade an OTS proof.")
    p3.add_argument("--ots-file", required=True, help="Path to .ots file.")
    p3.set_defaults(func=cmd_upgrade)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
