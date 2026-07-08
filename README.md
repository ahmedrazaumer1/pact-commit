# pact-commit

A reference implementation of the **Provable Address-Control Timestamp** (PACT) commitment format described in Robinson (2026, *Paradigm Research*) and analyzed in Raza (2026, *Quantum Sunset Economics*, working paper).

> **Status: research preview, draft v0.1.** This implementation is a faithful translation of the construction in Robinson's published proposal. The commitment format is a *draft* and may change before any consensus standard is adopted. Holders should treat commitments produced by this tool as best-effort artifacts whose redemption value depends on a future Bitcoin protocol upgrade that may or may not honor this exact format.
>
> This tool generates the **commitment side** of the protocol only. The **rescue-redemption side** (STARK proof generation against the BIP-361 verifier) is out of scope and will require Bitcoin Core support that does not yet exist.

## What this does

For a Bitcoin address you control, `pact-commit`:

1. Generates a 256-bit cryptographically random salt.
2. Encodes a PACT-format message that commits to the network (`bitcoin-mainnet`), the scriptPubKey of your address, and the salt.
3. Asks you to produce a **BIP-322 full-message signature** for that message using your wallet (the tool does *not* hold your private keys).
4. Computes the canonical PACT commitment hash:
   `commitment = SHA256("PACT/v1 commitment" || salt || SHA256(control_proof))`
5. Submits the commitment hash to OpenTimestamps for inclusion in a Bitcoin OP_RETURN.
6. Saves the salt, the BIP-322 signature, and the OpenTimestamps proof file as a single recovery artifact you must back up securely.

What the tool **never** does:

- Touch your private keys.
- Move any coins.
- Send the salt or the BIP-322 signature to OpenTimestamps or any other server (only the opaque commitment hash is submitted).
- Publish anything publicly attributable to you on-chain.

## Install

Requirements: Python 3.10+ on Linux, macOS, or Windows (WSL).

```bash
git clone https://github.com/ahmedrazaumer1/pact-commit.git
cd pact-commit
python -m pip install -r requirements.txt
```

Dependencies are minimal (`opentimestamps-client`, `coincurve`, plus the standard library).

## Usage

### Step 1 — Generate the message you need to sign

```bash
python pact_commit.py prepare \
    --network bitcoin-mainnet \
    --script-pubkey <hex-encoded scriptPubKey of your address> \
    --output prepared.json
```

This produces a `prepared.json` containing the PACT-format message string. You **never** type your private key into this tool.

### Step 2 — Sign the message externally with your wallet

Use any wallet that supports BIP-322 full-message signing (Bitcoin Core 24+, Sparrow, several hardware-wallet companions). Sign the message string from `prepared.json`. Save the resulting signature to a text file.

### Step 3 — Build and submit the commitment

```bash
python pact_commit.py finalize \
    --prepared prepared.json \
    --signature <path-to-signature-file> \
    --out-dir ./pact-artifacts/
```

This:

- Verifies the signature is a valid BIP-322 proof for your scriptPubKey.
- Computes the commitment hash.
- Submits the commitment to OpenTimestamps.
- Writes three files to `./pact-artifacts/`:
  - `commitment.hex`: the 32-byte commitment hash you submitted (public).
  - `recovery.json`: the salt, the BIP-322 signature, and metadata (**SECRET: back up like a private key**).
  - `commitment.ots`: the OpenTimestamps proof file (back up alongside `recovery.json`).

### Step 4 — Wait for confirmation, then upgrade the OTS proof

OpenTimestamps proofs become Bitcoin-block-anchored after roughly 2–6 hours. Run:

```bash
python pact_commit.py upgrade --ots-file ./pact-artifacts/commitment.ots
```

You can re-run this at any time. Once the proof is "complete" the OTS file will be updated with the Bitcoin block hash that anchors your commitment.

## What you must back up

Your **recovery artifact** is the bundle:

- `recovery.json` (contains the salt and BIP-322 signature)
- `commitment.ots` (the upgraded OpenTimestamps proof)

If you lose either file, the commitment is unredeemable. If a malicious party gains access to `recovery.json` *and* the eventual rescue protocol is deployed, they could in principle redeem your commitment. Treat it with the same care as a wallet backup.

## Multiple addresses

To commit for multiple addresses, run the prepare/finalize loop once per address. Each commitment uses an independent random salt and is unlinkable from the others on the public chain.

## Security model

The construction's security is derived from:

- **Hash collision resistance** of SHA-256 (post-quantum reduced to ~128-bit security under Grover; still adequate for the protective horizon).
- **OpenTimestamps integrity:** that the calendar server cannot retroactively forge an earlier timestamp than the one it actually published.
- **Bitcoin chain integrity:** that the OTS-anchored block remains in the canonical chain.

The commitment reveals nothing about which address is committed for, the size of the holding, or the holder's identity, *provided* that:

- The OpenTimestamps submission is made over a network path that cannot be tied to the holder's other on-chain identity (e.g., over Tor or a privacy-preserving network).
- The BIP-322 signing operation does not leak side-channel information through wallet software, signing devices, or telemetry.
- The recovery artifact is stored in a manner that does not correlate it with the holder's other records.

The threat model and limitations are discussed in detail in Section 5 of the accompanying paper.

## License

MIT License. See `LICENSE`.

## Citation

If you use this tool, please cite:

> Raza, A. (2026). *Quantum Sunset Economics: A Game-Theoretic and Empirical Analysis of Bitcoin's Most Consequential Soft Fork.* Working paper (v2, July 2026). SSRN: https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6901220.

and the Robinson proposal it implements:

> Robinson, D. (2026). *PACTs: Protecting Your Bitcoin From a Quantum Sunset.* Paradigm Research. https://www.paradigm.xyz/2026/05/pacts-protecting-your-bitcoin-from-a-quantum-sunset

## See also

- **Public peer review.** The paper's methodology was discussed on Delving Bitcoin, where Adam Gibson (AdamISZ) engaged at length. Gibson's methodological critique shaped the v2 revision, which moved the headline exposed-supply figure from 25.30% to 35.30%. Thread: [Quantum Sunset Economics: a working paper analyzing PACT adoption](https://delvingbitcoin.org/t/quantum-sunset-economics-a-working-paper-analyzing-pact-adoption/2645).
- **Empirical measurement code.** The BigQuery UTXO cohort analysis that produces the §3 exposure figures (including the 35.30% headline) lives separately from this reference implementation. It is described in Section 3 of the paper linked above.

## Coverage

- **Reuters, 8 July 2026.** [Crypto firms prepare defenses as quantum threat to encryption draws nearer](https://www.reuters.com/legal/government/crypto-firms-prepare-defenses-quantum-threat-encryption-draws-nearer-2026-07-08/), by Hannah Lang. Cites the paper's approximately 35 percent figure for Bitcoin's quantum-exposed supply.

## Disclaimer

This is a research artifact, not a production tool. The PACT commitment format is a draft. Bitcoin may never implement a rescue protocol that recognizes commitments in this format. Do not rely on PACTs as your sole quantum-protection strategy. Do not use this tool in any production custody flow.
