"""
Integration test for share rotation.

Based on: specs/001-1-purpose-scope/quickstart.md

Tests MUST fail before implementation (TDD).
"""

# Import decrypt helper from emergency_recovery tests
import base64
import io
import sys
from pathlib import Path

import pytest
import yaml

from src.crypto.bip39 import decode_share, parse_indexed_share
from src.crypto.encryption import EncryptedMessage, decrypt_message
from src.crypto.keypair import HybridKeypair, decrypt_private_keys
from src.crypto.shamir import reconstruct_secret
from tests.test_helpers import (
    create_test_vault,
    encrypt_test_message,
    extract_shares_from_output,
    get_vault_manifest,
)


def decrypt_vault_messages(vault_path: Path, shares: list) -> list:
    """
    Helper to decrypt all messages from a vault using shares.

    Args:
        vault_path: Path to vault file
        shares: List of BIP39 share mnemonics

    Returns:
        List of dicts with 'title' and 'plaintext' keys
    """
    with open(vault_path) as f:
        vault_data = yaml.safe_load(f)

    # Reconstruct passphrase from shares
    share_bytes = []
    for share_str in shares:
        index, mnemonic = parse_indexed_share(share_str)
        decoded = decode_share(mnemonic)
        share_bytes.append(bytes([index]) + decoded)

    passphrase = reconstruct_secret(share_bytes)

    # Decrypt private keys
    keypair_obj = HybridKeypair(
        rsa_public=vault_data["keys"]["public"]["rsa_4096"].encode(),
        rsa_private_encrypted=base64.b64decode(
            vault_data["keys"]["encrypted_private"]["rsa_4096"]
        ),
        kyber_public=base64.b64decode(vault_data["keys"]["public"]["kyber_1024"]),
        kyber_private_encrypted=base64.b64decode(
            vault_data["keys"]["encrypted_private"]["kyber_1024"]
        ),
        kdf_salt=base64.b64decode(vault_data["keys"]["encrypted_private"]["salt"]),
        kdf_iterations=vault_data["keys"]["encrypted_private"]["iterations"],
    )
    rsa_private, kyber_private = decrypt_private_keys(keypair_obj, passphrase)

    # Decrypt all messages
    decrypted_messages = []
    for msg_data in vault_data["messages"]:
        encrypted = EncryptedMessage(
            ciphertext=base64.b64decode(msg_data["ciphertext"]),
            rsa_wrapped_kek=base64.b64decode(msg_data["rsa_wrapped_kek"]),
            kyber_wrapped_kek=base64.b64decode(msg_data["kyber_wrapped_kek"]),
            nonce=base64.b64decode(msg_data["nonce"]),
            auth_tag=base64.b64decode(msg_data["tag"]),
        )
        plaintext = decrypt_message(
            encrypted, rsa_private, kyber_private, msg_data["title"]
        )
        decrypted_messages.append(
            {"title": msg_data["title"], "plaintext": plaintext.decode("utf-8")}
        )

    return decrypted_messages


class TestShareRotation:
    """Integration test for share rotation scenarios."""

    def test_initialize_vault_rotate_shares_change_k_n(self, tmp_path: Path) -> None:
        """Test: Initialize vault, rotate shares (change K/N)."""
        vault_path = tmp_path / "vault.yaml"

        # Step 1: Initialize 2-of-3 vault
        vault_path, old_shares = create_test_vault(tmp_path, k=2, n=3)
        assert len(old_shares) == 3

        # Step 2: Rotate to 3-of-5 (increase security)
        from src.cli.rotate import rotate_command

        # Capture output to extract new shares
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result = rotate_command(
                vault_path=str(vault_path),
                mode="shares",
                new_k=3,
                new_n=5,
                shares=old_shares[:2],  # Use 2 old shares (K=2)
                confirm=True,
            )
            assert result == 0, "Rotate command should succeed"

            output = captured_output.getvalue()
            new_shares = extract_shares_from_output(output)
        finally:
            sys.stdout = old_stdout

        # Expected: 5 new shares returned
        assert len(new_shares) == 5

        # Verify manifest updated
        manifest = get_vault_manifest(vault_path)
        assert manifest["threshold"]["k"] == 3
        assert manifest["threshold"]["n"] == 5

    def test_verify_new_shares_work_old_shares_fail(self, tmp_path: Path) -> None:
        """Test: Verify new shares work, old shares fail."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Initialize, encrypt, rotate
        vault_path, old_shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Test", "Secret content")

        # Rotate shares
        from src.cli.rotate import rotate_command

        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result = rotate_command(
                vault_path=str(vault_path),
                mode="shares",
                new_k=4,
                new_n=6,
                shares=old_shares[:3],
                confirm=True,
            )
            assert result == 0, "Rotate command should succeed"

            output = captured_output.getvalue()
            new_shares = extract_shares_from_output(output)
        finally:
            sys.stdout = old_stdout

        # Test 1: New shares work
        messages = decrypt_vault_messages(vault_path, new_shares[:4])
        assert len(messages) == 1
        assert messages[0]["plaintext"] == "Secret content"

        # Test 2: Old shares fail (wrong passphrase after rotation)
        from src.cli.decrypt import decrypt_command

        # Old shares (3) don't meet the new threshold (K=4), should fail with insufficient shares
        result = decrypt_command(vault_path=str(vault_path), shares=old_shares[:3])
        # Exit code 3 = insufficient shares
        assert result == 3, f"Expected exit code 3 (insufficient shares), got {result}"

    def test_messages_not_reencrypted_efficiency(self, tmp_path: Path) -> None:
        """Test: Messages not re-encrypted (efficiency check)."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Initialize and encrypt
        vault_path, old_shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Message 1", "Content 1")
        encrypt_test_message(vault_path, "Message 2", "Content 2")

        # Record original ciphertexts
        with open(vault_path) as f:
            vault_before = yaml.safe_load(f)
        ciphertexts_before = [msg["ciphertext"] for msg in vault_before["messages"]]

        # Rotate shares (not passphrase)
        from src.cli.rotate import rotate_command

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()

        try:
            result = rotate_command(
                vault_path=str(vault_path),
                mode="shares",
                new_k=4,
                new_n=6,
                shares=old_shares[:3],
                confirm=True,
            )
            assert result == 0, "Rotate command should succeed"
        finally:
            sys.stdout = old_stdout

        # Verify ciphertexts unchanged
        with open(vault_path) as f:
            vault_after = yaml.safe_load(f)
        ciphertexts_after = [msg["ciphertext"] for msg in vault_after["messages"]]

        assert (
            ciphertexts_before == ciphertexts_after
        ), "Messages should NOT be re-encrypted during share rotation"

    def test_passphrase_rotation_reencrypts_private_keys_only(self, tmp_path: Path) -> None:
        """Test: Passphrase rotation re-encrypts private keys only (not messages)."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Initialize and encrypt
        vault_path, old_shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Test", "Secret")

        # Record original private keys and message ciphertexts
        with open(vault_path) as f:
            vault_before = yaml.safe_load(f)
        encrypted_private_before = vault_before["keys"]["encrypted_private"]["rsa_4096"]
        message_ciphertext_before = vault_before["messages"][0]["ciphertext"]

        # Rotate passphrase
        from src.cli.rotate import rotate_command

        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result = rotate_command(
                vault_path=str(vault_path),
                mode="passphrase",
                new_k=3,
                new_n=5,
                shares=old_shares[:3],
                confirm=True,
            )
            assert result == 0, "Rotate command should succeed"

            output = captured_output.getvalue()
            new_shares = extract_shares_from_output(output)
        finally:
            sys.stdout = old_stdout

        # Verify private keys changed (re-encrypted)
        with open(vault_path) as f:
            vault_after = yaml.safe_load(f)
        encrypted_private_after = vault_after["keys"]["encrypted_private"]["rsa_4096"]
        assert (
            encrypted_private_before != encrypted_private_after
        ), "Private keys should be re-encrypted"

        # Verify message ciphertext unchanged
        message_ciphertext_after = vault_after["messages"][0]["ciphertext"]
        assert (
            message_ciphertext_before == message_ciphertext_after
        ), "Messages should NOT be re-encrypted"

    def test_rotation_history_logged_in_manifest(self, tmp_path: Path) -> None:
        """Test: Rotation events logged in manifest.rotation_history."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Initialize
        vault_path, shares_1 = create_test_vault(tmp_path, k=3, n=5)

        from src.cli.rotate import rotate_command

        # Perform 3 rotations
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            # Rotation 1: Share rotation (3-of-5 → 4-of-6)
            result = rotate_command(
                vault_path=str(vault_path),
                mode="shares",
                new_k=4,
                new_n=6,
                shares=shares_1[:3],
                confirm=True,
            )
            assert result == 0

            output = captured_output.getvalue()
            shares_2 = extract_shares_from_output(output)

            # Rotation 2: Passphrase rotation (keep 4-of-6)
            sys.stdout = captured_output = io.StringIO()
            result = rotate_command(
                vault_path=str(vault_path),
                mode="passphrase",
                new_k=4,
                new_n=6,
                shares=shares_2[:4],
                confirm=True,
            )
            assert result == 0

            output = captured_output.getvalue()
            shares_3 = extract_shares_from_output(output)

            # Rotation 3: Share rotation (4-of-6 → 3-of-5)
            sys.stdout = captured_output = io.StringIO()
            result = rotate_command(
                vault_path=str(vault_path),
                mode="shares",
                new_k=3,
                new_n=5,
                shares=shares_3[:4],
                confirm=True,
            )
            assert result == 0
        finally:
            sys.stdout = old_stdout

        # Verify rotation history
        with open(vault_path) as f:
            vault = yaml.safe_load(f)
        history = vault["manifest"]["rotation_history"]

        # Expected: 4 events (initial_creation + 3 rotations)
        assert len(history) == 4
        assert history[0]["event"] == "initial_creation"
        assert history[1]["event"] in ["share_rotation", "k_n_change"]
        assert history[2]["event"] == "passphrase_rotation"
        assert history[3]["event"] in ["share_rotation", "k_n_change"]

    def test_multiple_rotations_cascade(self, tmp_path: Path) -> None:
        """Test: Multiple rotations in sequence (cascade)."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Initialize and encrypt
        vault_path, shares_v1 = create_test_vault(tmp_path, k=2, n=3)
        original_message = "Persistent secret across rotations"
        encrypt_test_message(vault_path, "Persistent", original_message)

        from src.cli.decrypt import decrypt_command
        from src.cli.rotate import rotate_command

        old_stdout = sys.stdout

        # Rotation 1: 2-of-3 → 3-of-5
        sys.stdout = captured_output = io.StringIO()
        try:
            result = rotate_command(
                vault_path=str(vault_path),
                mode="shares",
                new_k=3,
                new_n=5,
                shares=shares_v1[:2],
                confirm=True,
            )
            assert result == 0
            output = captured_output.getvalue()
            shares_v2 = extract_shares_from_output(output)
        finally:
            sys.stdout = old_stdout

        # Rotation 2: 3-of-5 → 4-of-7 (share rotation)
        sys.stdout = captured_output = io.StringIO()
        try:
            result = rotate_command(
                vault_path=str(vault_path),
                mode="shares",
                new_k=4,
                new_n=7,
                shares=shares_v2[:3],
                confirm=True,
            )
            assert result == 0
            output = captured_output.getvalue()
            shares_v3 = extract_shares_from_output(output)
        finally:
            sys.stdout = old_stdout

        # Rotation 3: Passphrase rotation (keep 4-of-7)
        sys.stdout = captured_output = io.StringIO()
        try:
            result = rotate_command(
                vault_path=str(vault_path),
                mode="passphrase",
                new_k=4,
                new_n=7,
                shares=shares_v3[:4],
                confirm=True,
            )
            assert result == 0
            output = captured_output.getvalue()
            shares_v4 = extract_shares_from_output(output)
        finally:
            sys.stdout = old_stdout

        # Verify message still decryptable with final shares
        messages = decrypt_vault_messages(vault_path, shares_v4[:4])
        assert len(messages) == 1
        assert messages[0]["plaintext"] == original_message

        # Verify all old shares fail (insufficient for new thresholds)
        # shares_v1 (2 shares) < new threshold (4)
        result1 = decrypt_command(vault_path=str(vault_path), shares=shares_v1[:2])
        assert result1 == 3, f"shares_v1 should fail with insufficient shares, got {result1}"

        # shares_v2 (3 shares) < new threshold (4)
        result2 = decrypt_command(vault_path=str(vault_path), shares=shares_v2[:3])
        assert result2 == 3, f"shares_v2 should fail with insufficient shares, got {result2}"

        # shares_v3 (4 shares) would meet threshold BUT passphrase changed, so they reconstruct wrong passphrase
        # This should fail with decryption error
        with pytest.raises(Exception):
            decrypt_vault_messages(vault_path, shares_v3[:4])

    def test_rotation_requires_k_shares(self, tmp_path: Path) -> None:
        """Test: Rotation requires at least K shares (security check)."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Initialize 3-of-5 vault
        vault_path, old_shares = create_test_vault(tmp_path, k=3, n=5)

        # Attempt rotation with only 2 shares (K-1)
        from src.cli.rotate import rotate_command

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()

        try:
            # Expected: Should fail with exit code 3 (insufficient shares)
            result = rotate_command(
                vault_path=str(vault_path),
                mode="shares",
                new_k=4,
                new_n=6,
                shares=old_shares[:2],  # Only 2 shares (need 3)
                confirm=True,
            )
        finally:
            sys.stdout = old_stdout

        # Verify it failed with the correct exit code
        assert result == 3, f"Should fail with exit code 3 for insufficient shares, got {result}"
