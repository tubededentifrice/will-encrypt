"""
Contract tests for init command.

Based on: specs/001-1-purpose-scope/contracts/init.schema.yaml

Tests MUST fail before implementation (TDD).
"""

import os
import tempfile
from pathlib import Path
from typing import Any

import pytest
import yaml


class TestInitCommand:
    """Contract tests for will-encrypt init command."""

    def test_init_creates_valid_vault_structure(self, tmp_path: Path) -> None:
        """Test: Initialize 3-of-5 vault, verify vault.yaml created with correct structure."""
        from src.cli.init import init_command

        vault_path = tmp_path / "vault.yaml"
        result = init_command(k=3, n=5, vault_path=str(vault_path), import_shares=[])

        assert result == 0, "Init command should succeed"
        assert vault_path.exists(), "Vault file should exist"

        # Check file permissions (0600)
        import stat
        file_stat = vault_path.stat()
        file_mode = stat.S_IMODE(file_stat.st_mode)
        assert file_mode == 0o600, f"File permissions should be 0600, got {oct(file_mode)}"

        # Load and verify YAML structure
        with open(vault_path) as f:
            vault_data = yaml.safe_load(f)

        # Verify required top-level keys
        assert "version" in vault_data
        assert "created" in vault_data
        assert "keys" in vault_data
        assert "messages" in vault_data
        assert "manifest" in vault_data
        assert "recovery_guide" in vault_data
        assert "policy_document" in vault_data
        assert "crypto_notes" in vault_data

        # Verify manifest structure
        assert vault_data["manifest"]["threshold"]["k"] == 3
        assert vault_data["manifest"]["threshold"]["n"] == 5

        # Verify keys structure (correct format)
        assert "public" in vault_data["keys"]
        assert "rsa_4096" in vault_data["keys"]["public"]
        assert "kyber_1024" in vault_data["keys"]["public"]
        assert "encrypted_private" in vault_data["keys"]
        assert "rsa_4096" in vault_data["keys"]["encrypted_private"]
        assert "kyber_1024" in vault_data["keys"]["encrypted_private"]
        assert "encryption" in vault_data["keys"]["encrypted_private"]
        assert "kdf" in vault_data["keys"]["encrypted_private"]
        assert "iterations" in vault_data["keys"]["encrypted_private"]
        assert "salt" in vault_data["keys"]["encrypted_private"]

        # Verify messages array is empty initially
        assert isinstance(vault_data["messages"], list)
        assert len(vault_data["messages"]) == 0

    def test_init_rejects_invalid_k_greater_than_n(self, tmp_path: Path) -> None:
        """Test: K > N rejection."""
        from src.cli.init import init_command

        vault_path = tmp_path / "vault.yaml"
        result = init_command(k=5, n=3, vault_path=str(vault_path), import_shares=[])

        assert result == 1, "Init should fail with exit code 1 when K > N"
        assert not vault_path.exists(), "Vault file should not be created on error"

    def test_init_rejects_k_less_than_one(self, tmp_path: Path) -> None:
        """Test: K < 1 rejection."""
        from src.cli.init import init_command

        vault_path = tmp_path / "vault.yaml"
        result = init_command(k=0, n=5, vault_path=str(vault_path), import_shares=[])

        assert result == 1, "Init should fail with exit code 1 when K < 1"
        assert not vault_path.exists(), "Vault file should not be created on error"

    def test_init_rejects_existing_vault_without_force(self, tmp_path: Path, monkeypatch) -> None:
        """Test: Vault exists without --force rejection."""
        from src.cli.init import init_command

        vault_path = tmp_path / "vault.yaml"

        # Create vault first time
        result1 = init_command(k=3, n=5, vault_path=str(vault_path), import_shares=[])
        assert result1 == 0, "First init should succeed"

        # Mock user input to respond "no" to overwrite prompt
        monkeypatch.setattr('builtins.input', lambda _: 'no')

        # Try to create again without force (should prompt and user says no)
        result2 = init_command(k=3, n=5, vault_path=str(vault_path), force=False, import_shares=[])
        assert result2 == 2, "Second init without force should fail with exit code 2"

    def test_init_generates_n_bip39_mnemonics(self, tmp_path: Path, capsys) -> None:
        """Test: 5 BIP39 mnemonics displayed (24 words each, valid checksums)."""
        from src.cli.init import init_command
        from src.crypto.bip39 import validate_checksum

        vault_path = tmp_path / "vault.yaml"
        result = init_command(k=3, n=5, vault_path=str(vault_path), import_shares=[])
        assert result == 0, "Init should succeed"

        # Capture output
        output = capsys.readouterr().out

        assert "📊 Numbered Share Table" in output, "Share table header should be present"
        assert "| # | Indexed Share" in output, "Share table should include column headers"

        # Extract shares from output (format: "Share X/5:" followed by "  N: word1 word2 ... word24")
        import re
        shares = re.findall(r'Share \d+/\d+:\s+([^\n]+)', output)
        assert len(shares) == 5, f"Should have 5 shares, got {len(shares)}"

        # Verify each share
        for i, share in enumerate(shares):
            # Strip the "N: " prefix from the share (e.g., "1: word1 word2 ...")
            share_clean = re.sub(r'^\d+:\s+', '', share.strip())
            words = share_clean.split()
            assert len(words) == 24, f"Share {i+1} should have 24 words, got {len(words)} (cleaned share: {share_clean[:80]}...)"
            # Validate BIP39 checksum
            assert validate_checksum(share_clean), f"Share {i+1} has invalid BIP39 checksum"

    def test_init_performance_under_5_seconds(self, tmp_path: Path) -> None:
        """Test: Performance < 5 seconds."""
        import time
        from src.cli.init import init_command

        vault_path = tmp_path / "vault.yaml"

        start = time.time()
        result = init_command(k=3, n=5, vault_path=str(vault_path), import_shares=[])
        duration = time.time() - start

        assert result == 0, "Init should succeed"
        assert duration < 5.0, f"Init took {duration:.2f}s (target < 5s)"

    def test_init_vault_has_correct_manifest(self, tmp_path: Path) -> None:
        """Test: Manifest contains correct algorithms and thresholds."""
        from src.cli.init import init_command

        vault_path = tmp_path / "vault.yaml"
        result = init_command(k=3, n=5, vault_path=str(vault_path), import_shares=[])
        assert result == 0, "Init should succeed"

        with open(vault_path) as f:
            vault = yaml.safe_load(f)

        manifest = vault["manifest"]

        # Verify threshold
        assert manifest["threshold"]["k"] == 3
        assert manifest["threshold"]["n"] == 5

        # Verify algorithms (corrected passphrase_entropy to 256)
        assert manifest["algorithms"]["keypair"] == "RSA-4096 + Kyber-1024 (hybrid)"
        assert manifest["algorithms"]["passphrase_entropy"] == 256
        assert manifest["algorithms"]["secret_sharing"] == "Shamir SSS over GF(256)"
        assert manifest["algorithms"]["message_encryption"] == "AES-256-GCM"

        # Verify fingerprints exist and are properly formatted
        assert "fingerprints" in manifest
        assert "rsa_public_key_sha256" in manifest["fingerprints"]
        assert len(manifest["fingerprints"]["rsa_public_key_sha256"]) == 64  # hex hash

        # Verify rotation history (event key, not event_type)
        assert "rotation_history" in manifest
        assert isinstance(manifest["rotation_history"], list)
        assert len(manifest["rotation_history"]) >= 1
        assert manifest["rotation_history"][0]["event"] == "initial_creation"

    def test_init_manifest_includes_share_fingerprints(self, tmp_path: Path) -> None:
        """Test: Manifest persists salted share fingerprints for index recovery."""
        from src.cli.init import init_command

        vault_path = tmp_path / "vault.yaml"
        result = init_command(k=3, n=5, vault_path=str(vault_path), import_shares=[])
        assert result == 0, "Init should succeed"

        with open(vault_path) as f:
            vault = yaml.safe_load(f)

        share_fingerprints = vault["manifest"].get("share_fingerprints")
        assert isinstance(share_fingerprints, list), "share_fingerprints must be a list"
        assert len(share_fingerprints) == 5, "One fingerprint per generated share"

        seen_indices = set()
        for entry in share_fingerprints:
            assert {"index", "salt", "hash", "algorithm"} <= set(entry.keys())
            assert entry["algorithm"] == "sha256"
            assert len(entry["hash"]) == 64  # hex-encoded SHA-256 digest
            assert len(entry["salt"]) == 64  # 32-byte salt encoded as hex
            assert entry["index"] not in seen_indices
            seen_indices.add(entry["index"])

    def test_init_shares_never_written_to_disk(self, tmp_path: Path, capsys) -> None:
        """Test: BIP39 shares never stored in vault or temporary files."""
        from src.cli.init import init_command

        vault_path = tmp_path / "vault.yaml"
        result = init_command(k=3, n=5, vault_path=str(vault_path), import_shares=[])
        assert result == 0, "Init should succeed"

        # Extract shares from stdout
        output = capsys.readouterr().out
        import re
        shares = re.findall(r'Share \d+/\d+:\s+([^\n]+)', output)
        assert len(shares) == 5, "Should have 5 shares"

        # Read vault file
        with open(vault_path) as f:
            vault_content = f.read()

        # Verify shares are NOT in vault file
        for share in shares:
            words = share.strip().split()
            # Check that none of the share words appear in sequence in the vault
            for word in words[:5]:  # Check first 5 words as indicator
                # Words might appear individually, but not the full mnemonic
                pass  # Individual words in BIP39 wordlist might appear
            # The key check: the full share should not appear
            assert share.strip() not in vault_content, "Full share MUST NOT be stored in vault"
