"""
Contract tests for rotate command.

Based on: specs/001-1-purpose-scope/contracts/rotate.schema.yaml

Tests MUST fail before implementation (TDD).
"""

import io
import sys
from pathlib import Path

import pytest
import yaml

from tests.test_helpers import (
    create_test_vault,
    decrypt_test_vault,
    encrypt_test_message,
    get_vault_manifest,
    get_vault_messages,
    validate_bip39_share,
)


class TestRotateCommand:
    """Contract tests for will-encrypt rotate command."""

    def test_share_rotation_same_passphrase(self, tmp_path: Path) -> None:
        """Test: Share rotation (same passphrase, new K/N), verify new shares work."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create 3-of-5 vault and encrypt a message
        vault_path, old_shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Test", "Secret")

        # Capture output to extract new shares
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
                confirm=True,  # Skip confirmation prompt for testing
            )
            output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        # Expected: Exit code 0, 6 new shares returned
        assert result == 0, "Rotation should succeed"

        assert "Share 1/" in output, "Share table headers should be present"
        assert "|" in output and "+" in output, "ASCII table structure should be present"

        # Extract new shares from output
        from tests.test_helpers import extract_shares_from_output

        new_shares = extract_shares_from_output(output)
        assert len(new_shares) == 6, f"Expected 6 new shares, got {len(new_shares)}"

        # Each new share is valid BIP39 mnemonic (without the index prefix)
        from src.crypto.bip39 import parse_indexed_share
        for i, share in enumerate(new_shares, 1):
            _, mnemonic = parse_indexed_share(share)
            assert validate_bip39_share(mnemonic), f"Share {i} should be valid BIP39"

        # Verify manifest updated
        manifest = get_vault_manifest(vault_path)
        # Manifest structure has threshold dict with k and n
        threshold = manifest.get("threshold", {})
        assert threshold.get("k") == 4, "Threshold K should be updated to 4"
        assert threshold.get("n") == 6, "Threshold N should be updated to 6"

        # New shares can decrypt messages (use 4 of the 6 new shares)
        result = decrypt_test_vault(vault_path, new_shares[:4])
        assert result == 0, "Should be able to decrypt with new shares"

    def test_share_rotation_interactive_accepts_indexed_shares(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Interactive share rotation accepts indexed mnemonics and preserves indices."""
        vault_path, old_shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Test", "Secret")

        # Provide non-sequential share numbers (1, 3, 5) to ensure original indices are reused
        share_inputs = iter([old_shares[0], old_shares[2], old_shares[4]])

        def fake_input(_prompt: str = "") -> str:
            return next(share_inputs)

        monkeypatch.setattr("builtins.input", fake_input)

        from src.cli.rotate import rotate_command

        result = rotate_command(
            vault_path=str(vault_path),
            mode="shares",
            new_k=3,
            new_n=5,
            shares=None,
            confirm=True,
        )

        assert result == 0, "Interactive rotation should succeed with indexed shares"

        captured = capsys.readouterr()
        assert "Share 1/" in captured.out, "Share table headers should be present"
        assert "|" in captured.out and "+" in captured.out, "ASCII table structure should be present"
        from tests.test_helpers import extract_shares_from_output

        new_shares = extract_shares_from_output(captured.out)
        assert len(new_shares) == 5, "Expected 5 new shares from rotation output"

        # Ensure the formatted shares keep their indices ("N: mnemonic")
        for share in new_shares:
            prefix, _, mnemonic = share.partition(":")
            assert prefix.strip().isdigit(), "Share must retain numeric prefix"
            assert validate_bip39_share(mnemonic.strip()), "Mnemonic portion must remain valid"

        # New shares should decrypt successfully
        decrypt_result = decrypt_test_vault(vault_path, new_shares[:3])
        assert decrypt_result == 0, "Newly rotated shares should decrypt vault"

    def test_share_rotation_requires_indexed_cli_shares(self, tmp_path: Path) -> None:
        """Non-interactive rotation rejects shares without explicit indices."""
        vault_path, old_shares = create_test_vault(tmp_path, k=3, n=5)

        bare_shares = [share.split(":", 1)[1].strip() for share in old_shares[:3]]

        from src.cli.rotate import rotate_command

        result = rotate_command(
            vault_path=str(vault_path),
            mode="shares",
            new_k=4,
            new_n=6,
            shares=bare_shares,
            confirm=True,
        )

        assert result == 5, "Rotation must fail when share indices are omitted"

    def test_passphrase_rotation_new_passphrase(self, tmp_path: Path) -> None:
        """Test: Passphrase rotation (new passphrase), verify private keys re-encrypted."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault and encrypt message
        vault_path, old_shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Test", "Secret")

        # Rotate passphrase (keep K=3, N=5)
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
                confirm=True,  # Skip confirmation prompt for testing
            )
            output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        # Expected: Exit code 0, new passphrase generated
        assert result == 0, "Passphrase rotation should succeed"

        assert "Share 1/" in output, "Share table headers should be present"
        assert "|" in output and "+" in output, "ASCII table structure should be present"

        # Extract new shares from output
        from tests.test_helpers import extract_shares_from_output

        new_shares = extract_shares_from_output(output)
        assert len(new_shares) == 5, f"Expected 5 new shares, got {len(new_shares)}"

        # New shares are different from old shares
        assert new_shares != old_shares, "New shares should differ from old shares"

        # New shares can decrypt messages
        result = decrypt_test_vault(vault_path, new_shares[:3])
        assert result == 0, "Should be able to decrypt with new shares"

        # Old shares cannot decrypt anymore (attempting would fail)
        # Note: We can't easily test this without expecting an error, so we skip

        # Manifest rotation_history has passphrase_rotation event
        manifest = get_vault_manifest(vault_path)
        rotation_history = manifest.get("rotation_history", [])
        # Should have 2 events: initial_creation + passphrase_rotation
        assert len(rotation_history) >= 2, "Rotation history should have at least 2 events"
        # Find passphrase rotation event (field is "event", not "event_type")
        passphrase_rotations = [e for e in rotation_history if e.get("event") == "passphrase_rotation"]
        assert len(passphrase_rotations) >= 1, "Should have at least 1 passphrase rotation event"

    def test_old_shares_invalid_after_rotation(self, tmp_path: Path) -> None:
        """Test: Old shares invalid after rotation."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault and encrypt a message
        vault_path, old_shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Test", "Secret")

        # Verify old shares work before rotation
        result_before = decrypt_test_vault(vault_path, old_shares[:3])
        assert result_before == 0, "Old shares should work before rotation"

        # Rotate to PASSPHRASE mode (not share mode) to get a new passphrase
        # This will make old shares invalid
        from src.cli.rotate import rotate_command

        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result = rotate_command(
                vault_path=str(vault_path),
                mode="passphrase",  # Changed to passphrase mode
                new_k=3,
                new_n=5,
                shares=old_shares[:3],
                confirm=True,  # Skip confirmation prompt for testing
            )
            output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        assert result == 0, "Rotation should succeed"

        assert "Share 1/" in output, "Share table headers should be present"
        assert "|" in output and "+" in output, "ASCII table structure should be present"

        # Attempt decrypt with old shares - should fail with new passphrase
        # The decrypt will fail because a new passphrase was generated
        result_after = decrypt_test_vault(vault_path, old_shares[:3])
        assert result_after != 0, "Old shares should not work after passphrase rotation"

    def test_rotation_requires_k_shares(self, tmp_path: Path) -> None:
        """Test: Rotation requires at least K shares."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create 3-of-5 vault
        vault_path, old_shares = create_test_vault(tmp_path, k=3, n=5)

        # Attempt rotation with only 2 shares (K-1)
        # Expected: Exit code 3 (insufficient shares)
        from src.cli.rotate import rotate_command

        result = rotate_command(
            vault_path=str(vault_path),
            mode="shares",
            new_k=4,
            new_n=6,
            shares=old_shares[:2],  # Only 2 shares, but need 3
            confirm=True,  # Skip confirmation prompt for testing
        )

        assert result == 3, "Rotation should fail with exit code 3 for insufficient shares"

    def test_rotation_history_logged(self, tmp_path: Path) -> None:
        """Test: Rotation events logged in manifest.rotation_history."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault
        vault_path, old_shares = create_test_vault(tmp_path, k=3, n=5)

        # Check initial state
        manifest = get_vault_manifest(vault_path)
        initial_history_len = len(manifest.get("rotation_history", []))

        # Perform share rotation
        from src.cli.rotate import rotate_command

        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result1 = rotate_command(
                vault_path=str(vault_path),
                mode="shares",
                new_k=4,
                new_n=6,
                shares=old_shares[:3],
                confirm=True,  # Skip confirmation prompt for testing
            )
            output1 = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        assert result1 == 0, "First rotation should succeed"

        assert "📊 Numbered Share Table" in output1, "Share table header should be present"
        assert "|" in output1 and "+" in output1, "ASCII table structure should be present"

        # Extract new shares
        from tests.test_helpers import extract_shares_from_output

        shares_2 = extract_shares_from_output(output1)

        # Perform passphrase rotation
        sys.stdout = captured_output2 = io.StringIO()

        try:
            result2 = rotate_command(
                vault_path=str(vault_path),
                mode="passphrase",
                new_k=4,
                new_n=6,
                shares=shares_2[:4],
                confirm=True,  # Skip confirmation prompt for testing
            )
            output2 = captured_output2.getvalue()
        finally:
            sys.stdout = old_stdout

        assert result2 == 0, "Second rotation should succeed"

        assert "📊 Numbered Share Table" in output2, "Share table header should be present"
        assert "|" in output2 and "+" in output2, "ASCII table structure should be present"

        # Expected: rotation_history has initial + 2 rotations
        manifest = get_vault_manifest(vault_path)
        history = manifest.get("rotation_history", [])
        # Should have initial + 2 rotation events
        assert len(history) >= initial_history_len + 2, f"Should have added 2 rotation events, got {len(history)} total"

        # Check event types - extract "event" field (not "event_type")
        # History items are dicts when loaded from YAML
        event_types = []
        for e in history:
            if isinstance(e, dict):
                event_types.append(e.get("event"))  # Changed from "event_type" to "event"
            else:
                # It's a RotationEvent object
                event_types.append(e.event_type if hasattr(e, "event_type") else None)

        # Filter out None values and check
        valid_event_types = [et for et in event_types if et is not None]
        assert "share_rotation" in valid_event_types or "k_n_change" in valid_event_types, f"Should have share rotation event, got: {valid_event_types}"
        assert "passphrase_rotation" in valid_event_types, f"Should have passphrase rotation event, got: {valid_event_types}"

    def test_messages_not_reencrypted_during_share_rotation(self, tmp_path: Path) -> None:
        """Test: Messages not re-encrypted during share rotation (efficiency)."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault and encrypt message
        vault_path, old_shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Test", "Secret")

        # Record original message ciphertext
        messages_before = get_vault_messages(vault_path)
        original_ciphertext = messages_before[0]["ciphertext"]

        # Rotate shares (not passphrase)
        from src.cli.rotate import rotate_command

        result = rotate_command(
            vault_path=str(vault_path),
            mode="shares",
            new_k=4,
            new_n=6,
            shares=old_shares[:3],
            confirm=True,  # Skip confirmation prompt for testing
        )

        assert result == 0, "Rotation should succeed"

        # Verify ciphertext unchanged (messages not re-encrypted)
        messages_after = get_vault_messages(vault_path)
        assert len(messages_after) == 1, "Should still have 1 message"
        assert messages_after[0]["ciphertext"] == original_ciphertext, "Ciphertext should remain unchanged during share rotation"
