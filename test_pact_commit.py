"""Tests for pact_commit reference implementation.

Covers the deterministic parts of the protocol:
  - PACT message construction is canonical and reproducible
  - Commitment-hash construction is correct
  - Salt generation is 256-bit
  - Input validation rejects malformed inputs

The OpenTimestamps and BIP-322 verification paths are NOT covered here
because they require external services / Bitcoin Core. They are tested
manually per the README.
"""

import hashlib
import json
import unittest

import pact_commit


class TestPactMessage(unittest.TestCase):
    def test_message_is_canonical_json(self):
        msg = pact_commit.build_pact_message(
            network="bitcoin-mainnet",
            script_pubkey_hex="76a91488ac",
            salt_hex="00" * 32,
        )
        # JSON should parse and contain expected fields.
        parsed = json.loads(msg)
        self.assertEqual(parsed["version"], "PACT/v1")
        self.assertEqual(parsed["network"], "bitcoin-mainnet")
        self.assertEqual(parsed["scriptPubKey"], "76a91488ac")
        self.assertEqual(parsed["salt"], "00" * 32)
        # Keys are sorted.
        self.assertEqual(
            list(parsed.keys()),
            ["network", "purpose", "salt", "scriptPubKey", "version"],
        )

    def test_message_is_deterministic(self):
        a = pact_commit.build_pact_message(
            network="bitcoin-mainnet",
            script_pubkey_hex="abcd",
            salt_hex="11" * 32,
        )
        b = pact_commit.build_pact_message(
            network="bitcoin-mainnet",
            script_pubkey_hex="ABCD",  # uppercase normalized
            salt_hex="11" * 32,
        )
        self.assertEqual(a, b)

    def test_rejects_unsupported_network(self):
        with self.assertRaises(ValueError):
            pact_commit.build_pact_message(
                network="ethereum",
                script_pubkey_hex="00",
                salt_hex="00" * 32,
            )

    def test_rejects_short_salt(self):
        with self.assertRaises(ValueError):
            pact_commit.build_pact_message(
                network="bitcoin-mainnet",
                script_pubkey_hex="00",
                salt_hex="00" * 16,  # 128-bit, not 256
            )

    def test_rejects_non_hex_inputs(self):
        with self.assertRaises(ValueError):
            pact_commit.build_pact_message(
                network="bitcoin-mainnet",
                script_pubkey_hex="not-hex",
                salt_hex="00" * 32,
            )


class TestCommitment(unittest.TestCase):
    def test_commitment_matches_spec(self):
        # Manual reference computation. Salt = 0x11..., proof = b"sig".
        salt_hex = "11" * 32
        control_proof = b"sig"
        domain = b"PACT/v1 commitment"
        expected_inner = hashlib.sha256(control_proof).digest()
        expected_outer = hashlib.sha256(
            domain + bytes.fromhex(salt_hex) + expected_inner
        ).digest()

        actual = pact_commit.compute_commitment(
            salt_hex=salt_hex, control_proof_bytes=control_proof
        )
        self.assertEqual(actual, expected_outer)
        self.assertEqual(len(actual), 32)

    def test_commitment_changes_with_salt(self):
        c1 = pact_commit.compute_commitment(
            salt_hex="00" * 32, control_proof_bytes=b"sig"
        )
        c2 = pact_commit.compute_commitment(
            salt_hex="01" * 32, control_proof_bytes=b"sig"
        )
        self.assertNotEqual(c1, c2)

    def test_commitment_changes_with_proof(self):
        c1 = pact_commit.compute_commitment(
            salt_hex="00" * 32, control_proof_bytes=b"sig-a"
        )
        c2 = pact_commit.compute_commitment(
            salt_hex="00" * 32, control_proof_bytes=b"sig-b"
        )
        self.assertNotEqual(c1, c2)


class TestConstants(unittest.TestCase):
    def test_salt_size(self):
        self.assertEqual(pact_commit.SALT_BYTES, 32)

    def test_commitment_size(self):
        self.assertEqual(pact_commit.COMMITMENT_BYTES, 32)

    def test_version_string(self):
        self.assertEqual(pact_commit.PACT_VERSION, "PACT/v1")
        self.assertEqual(pact_commit.COMMITMENT_DOMAIN, "PACT/v1 commitment")


if __name__ == "__main__":
    unittest.main()
