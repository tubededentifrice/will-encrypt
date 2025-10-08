"""
Contract tests for decrypt command.

Based on: specs/001-1-purpose-scope/contracts/decrypt.schema.yaml

Tests MUST fail before implementation (TDD).
"""

import io
import sys
import time
from pathlib import Path

import pytest
import yaml

from tests.test_helpers import create_test_vault, encrypt_test_message


class TestDecryptCommand:
    """Contract tests for will-encrypt decrypt command."""

    def test_decrypt_with_k_valid_shares(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test: Decrypt with K valid shares, verify all messages recovered."""
        from src.cli.decrypt import decrypt_command

        # Setup: Create vault and encrypt messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)

        result1 = encrypt_test_message(vault_path, "Message 1", "Secret 1")
        assert result1 == 0, "Encrypt 1 should succeed"

        result2 = encrypt_test_message(vault_path, "Message 2", "Secret 2")
        assert result2 == 0, "Encrypt 2 should succeed"

        # Shares already have indices from create_test_vault (e.g., "1: word1 word2 ...")
        # Decrypt with 3 shares (K=3)
        result = decrypt_command(vault_path=str(vault_path), shares=shares[:3])

        # Expected: Exit code 0 (success)
        assert result == 0, "Decrypt should succeed with K valid shares"

        # Verify output contains both messages
        output = capsys.readouterr().out
        assert "Message 1" in output, "Output should contain Message 1"
        assert "Message 2" in output, "Output should contain Message 2"
        assert "Secret 1" in output, "Output should contain decrypted content 1"
        assert "Secret 2" in output, "Output should contain decrypted content 2"

    def test_decrypt_rejects_insufficient_shares(self, tmp_path: Path) -> None:
        """Test: Decrypt with K-1 shares rejection (insufficient shares)."""
        from src.cli.decrypt import decrypt_command

        # Setup: Create vault (K=3)
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)

        # Attempt decrypt with only 2 shares (K-1)
        result = decrypt_command(vault_path=str(vault_path), shares=shares[:2])

        # Expected: Exit code 3 (insufficient shares)
        assert result == 3, "Decrypt should fail with exit code 3 when insufficient shares"

    def test_decrypt_rejects_invalid_bip39_checksum(self, tmp_path: Path) -> None:
        """Test: Invalid BIP39 checksum rejection."""
        from src.cli.decrypt import decrypt_command

        # Setup: Create vault
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)

        # Corrupt one share (modify last word to break checksum)
        # Use a share with invalid checksum - repeat "abandon" 24 times has invalid checksum
        corrupted_share = "1: " + " ".join(["abandon"] * 24)
        corrupted_shares = [corrupted_share] + shares[1:3]

        # Expected: Exit code 4 (invalid share)
        result = decrypt_command(vault_path=str(vault_path), shares=corrupted_shares)
        assert result == 4, "Decrypt should fail with exit code 4 for invalid BIP39 checksum"

    def test_decrypt_performance_under_5_seconds_crypto(self, tmp_path: Path) -> None:
        """Test: Performance < 5 seconds crypto operations."""
        from src.cli.decrypt import decrypt_command

        # Setup: Create vault and encrypt messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)

        # Encrypt 10 messages
        for i in range(10):
            result = encrypt_test_message(vault_path, f"Message {i}", f"Content {i}")
            assert result == 0, f"Encrypt message {i} should succeed"

        # Measure crypto operations
        start = time.time()
        result = decrypt_command(vault_path=str(vault_path), shares=shares[:3])
        duration = time.time() - start

        # Expected: duration < 5.0 seconds
        assert result == 0, "Decrypt should succeed"
        assert duration < 5.0, f"Decrypt took {duration:.2f}s (target < 5s)"

    def test_decrypt_hybrid_verification(self, tmp_path: Path) -> None:
        """Test: Hybrid verification (RSA KEK == Kyber KEK)."""
        import base64

        from src.cli.decrypt import decrypt_command

        # Setup: Create vault and encrypt message
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        result = encrypt_test_message(vault_path, "Test", "Secret")
        assert result == 0, "Encrypt should succeed"

        # Manually corrupt one of the wrapped KEKs in vault to simulate tampering
        with open(vault_path) as f:
            vault_data = yaml.safe_load(f)

        # Corrupt the Kyber wrapped KEK with invalid base64 data
        vault_data["messages"][0]["kyber_wrapped_kek"] = base64.b64encode(b"corrupted_data").decode()

        with open(vault_path, "w") as f:
            yaml.dump(vault_data, f)

        # Expected: Exit code 7 (decryption error due to hybrid mismatch)
        result = decrypt_command(vault_path=str(vault_path), shares=shares[:3])
        assert result == 7, "Decrypt should fail with exit code 7 for hybrid verification failure"

    def test_decrypt_wrong_passphrase(self, tmp_path: Path) -> None:
        """Test: Wrong passphrase (from incorrect shares) rejection."""
        from src.cli.decrypt import decrypt_command
        from src.cli.init import init_command

        # Setup: Create vault
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)

        # Encrypt a message
        result = encrypt_test_message(vault_path, "Test", "Secret")
        assert result == 0, "Encrypt should succeed"

        # Generate wrong shares from a different vault in a different directory
        tmp_path_2 = tmp_path / "vault2"
        tmp_path_2.mkdir()
        vault_path_2 = tmp_path_2 / "vault2.yaml"

        # Capture output for second vault
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result = init_command(k=3, n=5, vault_path=str(vault_path_2), import_shares=[])
            assert result == 0, "Init second vault should succeed"
            output = sys.stdout.getvalue()
            from tests.test_helpers import extract_shares_from_output
            wrong_shares = extract_shares_from_output(output)
        finally:
            sys.stdout = old_stdout

        # Attempt decrypt with wrong shares (already have indices)
        # Expected: Exit code 7 (decryption error due to wrong passphrase)
        result = decrypt_command(vault_path=str(vault_path), shares=wrong_shares[:3])
        assert result == 7, "Decrypt should fail with exit code 7 for wrong passphrase"

    def test_decrypt_tampered_ciphertext_rejected(self, tmp_path: Path) -> None:
        """Test: Tampered ciphertext rejection (auth tag mismatch)."""
        import base64

        from src.cli.decrypt import decrypt_command

        # Setup: Create vault and encrypt message
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        result = encrypt_test_message(vault_path, "Test", "Secret")
        assert result == 0, "Encrypt should succeed"

        # Tamper with ciphertext
        with open(vault_path) as f:
            vault_data = yaml.safe_load(f)

        # Corrupt the ciphertext by changing some bytes
        original_ciphertext = base64.b64decode(vault_data["messages"][0]["ciphertext"])
        tampered_ciphertext = b"X" * len(original_ciphertext)
        vault_data["messages"][0]["ciphertext"] = base64.b64encode(tampered_ciphertext).decode()

        with open(vault_path, "w") as f:
            yaml.dump(vault_data, f)

        # Expected: Exit code 7 (decryption failed - auth tag mismatch)
        result = decrypt_command(vault_path=str(vault_path), shares=shares[:3])
        assert result == 7, "Decrypt should fail with exit code 7 for tampered ciphertext"

    def test_decrypt_auto_detects_share_indices(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Test: Decrypt auto-detects share indices from fingerprints when indices not provided."""
        from src.cli.decrypt import decrypt_command

        # Setup: Create vault and encrypt message
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        result = encrypt_test_message(vault_path, "Message", "Secret")
        assert result == 0, "Encrypt should succeed"

        # Strip indices from shares (simulate user providing only mnemonics)
        shares_without_indices = [share.split(":", 1)[1].strip() for share in shares[:3]]

        # Decrypt with shares without indices
        result = decrypt_command(vault_path=str(vault_path), shares=shares_without_indices)

        # Expected: Exit code 0 (success via auto-detection)
        assert result == 0, "Decrypt should succeed with auto-detected share indices"

        # Verify output contains auto-detection message
        output = capsys.readouterr().out
        assert "Auto-detected" in output, "Output should indicate auto-detection occurred"
        assert "Message" in output, "Output should contain message title"
        assert "Secret" in output, "Output should contain decrypted content"
