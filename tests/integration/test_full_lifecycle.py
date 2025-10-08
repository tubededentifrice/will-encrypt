"""
Integration test for full lifecycle.

Based on: specs/001-1-purpose-scope/quickstart.md (Steps 1-10)

Tests MUST fail before implementation (TDD).
"""

from pathlib import Path
import io
import sys
import json
import yaml

import pytest

from tests.test_helpers import (
    extract_shares_from_output,
    create_test_vault,
    encrypt_test_message,
    decrypt_test_vault,
    get_vault_manifest,
    get_vault_messages,
)


class TestFullLifecycle:
    """Integration test for complete vault lifecycle (10 steps from quickstart)."""

    def test_step_1_initialize_3_of_5_vault(self, tmp_path: Path) -> None:
        """Step 1: Initialize 3-of-5 threshold vault."""
        from src.cli.init import init_command

        vault_path = tmp_path / "test_vault.yaml"

        # Capture output to extract shares
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result = init_command(k=3, n=5, vault_path=str(vault_path), import_shares=[])
            output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        # Verify command succeeded
        assert result == 0, "Init command should succeed"

        # Verify vault file was created
        assert vault_path.exists(), "Vault file should exist"

        # Verify file permissions (0600)
        import stat
        file_stat = vault_path.stat()
        file_mode = stat.S_IMODE(file_stat.st_mode)
        assert file_mode == 0o600, f"File permissions should be 0600, got {oct(file_mode)}"

        # Verify shares were generated
        shares = extract_shares_from_output(output)
        assert len(shares) == 5, f"Expected 5 shares, got {len(shares)}"

    def test_step_2_encrypt_three_messages(self, tmp_path: Path) -> None:
        """Step 2: Encrypt 3 messages."""
        from src.cli.encrypt import encrypt_command

        # Setup: Initialize vault
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)

        # Encrypt 3 messages
        result1 = encrypt_command(
            vault_path=str(vault_path),
            title="Bank Passwords",
            message_text="Account: 123-456\nPassword: secret123"
        )
        assert result1 == 0, "Encrypt command 1 should succeed"

        result2 = encrypt_command(
            vault_path=str(vault_path),
            title="Estate Instructions",
            message_text="Executor: Jane Doe\nLawyer: John Smith"
        )
        assert result2 == 0, "Encrypt command 2 should succeed"

        result3 = encrypt_command(
            vault_path=str(vault_path),
            title="Digital Assets",
            message_text="Bitcoin wallet: bc1q...\nSeed phrase: abandon..."
        )
        assert result3 == 0, "Encrypt command 3 should succeed"

        # Verify messages added
        messages = get_vault_messages(vault_path)
        assert len(messages) == 3, f"Expected 3 messages, got {len(messages)}"

        # Verify message titles
        titles = [m["title"] for m in messages]
        assert "Bank Passwords" in titles
        assert "Estate Instructions" in titles
        assert "Digital Assets" in titles

    def test_step_3_list_messages_no_decryption(self, tmp_path: Path) -> None:
        """Step 3: List messages (no decryption)."""
        from src.cli.list import list_command

        # Setup: Initialize vault and encrypt messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Bank Passwords", "Account: 123-456\nPassword: secret123")
        encrypt_test_message(vault_path, "Estate Instructions", "Executor: Jane Doe\nLawyer: John Smith")
        encrypt_test_message(vault_path, "Digital Assets", "Bitcoin wallet: bc1q...\nSeed phrase: abandon...")

        # Capture output from list command
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result = list_command(vault_path=str(vault_path), format="table", sort_by="id")
            output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        assert result == 0, "List command should succeed"

        # Expected: Table with titles visible, no plaintext
        assert "Bank Passwords" in output, "Title should be visible"
        assert "Estate Instructions" in output, "Title should be visible"
        assert "Digital Assets" in output, "Title should be visible"
        assert "secret123" not in output, "Plaintext should NOT be visible"
        assert "Account: 123-456" not in output, "Plaintext should NOT be visible"

    def test_step_4_validate_vault(self, tmp_path: Path) -> None:
        """Step 4: Validate vault."""
        from src.cli.validate import validate_command

        # Setup: Initialize vault and encrypt messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Bank Passwords", "Account: 123-456\nPassword: secret123")
        encrypt_test_message(vault_path, "Estate Instructions", "Executor: Jane Doe\nLawyer: John Smith")

        # Validate
        result = validate_command(vault_path=str(vault_path), verbose=False)

        # Expected: All checks pass
        assert result == 0, "Validate command should succeed (exit code 0)"

    def test_step_5_emergency_recovery_3_shares_decrypt_all(self, tmp_path: Path) -> None:
        """Step 5: Emergency recovery (3 shares decrypt all)."""
        from src.cli.decrypt import decrypt_command

        # Setup: Initialize vault and encrypt messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Bank Passwords", "Account: 123-456\nPassword: secret123")
        encrypt_test_message(vault_path, "Estate Instructions", "Executor: Jane Doe\nLawyer: John Smith")
        encrypt_test_message(vault_path, "Digital Assets", "Bitcoin wallet: bc1q...\nSeed phrase: abandon...")

        # Decrypt with 3 shares (shares 1, 3, 5)
        selected_shares = [shares[0], shares[2], shares[4]]

        # Capture output to verify decrypted content
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result = decrypt_command(vault_path=str(vault_path), shares=selected_shares)
            output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        # Expected: Command succeeds and all 3 messages decrypted
        assert result == 0, "Decrypt command should succeed"
        assert "Account: 123-456" in output, "Message 1 should be decrypted"
        assert "Password: secret123" in output, "Message 1 should be decrypted"
        assert "Executor: Jane Doe" in output, "Message 2 should be decrypted"
        assert "Bitcoin wallet: bc1q" in output, "Message 3 should be decrypted"

    def test_step_6_insufficient_shares_negative_test(self, tmp_path: Path) -> None:
        """Step 6: Test insufficient shares (negative test)."""
        from src.cli.decrypt import decrypt_command

        # Setup: Initialize vault
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)

        # Attempt decrypt with only 2 shares (K-1)
        result = decrypt_command(vault_path=str(vault_path), shares=shares[:2])

        # Expected: Command should fail with exit code 3 (insufficient shares)
        assert result == 3, f"Decrypt should fail with exit code 3, got {result}"

    def test_step_7_share_rotation_3_of_5_to_4_of_6(self, tmp_path: Path) -> None:
        """Step 7: Share rotation (3-of-5 → 4-of-6)."""
        from src.cli.rotate import rotate_command

        # Setup: Initialize vault and encrypt messages
        vault_path, old_shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Bank Passwords", "Account: 123-456\nPassword: secret123")
        encrypt_test_message(vault_path, "Estate Instructions", "Executor: Jane Doe\nLawyer: John Smith")

        # Capture output to extract new shares
        old_stdout = sys.stdout
        sys.stdout = rotate_output_buffer = io.StringIO()

        try:
            # Rotate shares to 4-of-6
            result = rotate_command(
                vault_path=str(vault_path),
                mode="shares",
                new_k=4,
                new_n=6,
                shares=old_shares[:3],  # Use 3 old shares
                confirm=True  # Skip confirmation prompt for testing
            )
            rotate_output = rotate_output_buffer.getvalue()
        finally:
            sys.stdout = old_stdout

        # Expected: Command succeeds
        assert result == 0, "Rotate command should succeed"

        # Extract new shares from output
        new_shares = extract_shares_from_output(rotate_output)
        assert len(new_shares) == 6, f"Expected 6 new shares, got {len(new_shares)}"

        # Verify manifest was updated
        manifest = get_vault_manifest(vault_path)
        assert manifest["threshold"]["k"] == 4, "Threshold K should be updated to 4"
        assert manifest["threshold"]["n"] == 6, "Threshold N should be updated to 6"

    def test_step_8_verify_rotated_shares_work(self, tmp_path: Path) -> None:
        """Step 8: Verify rotated shares work."""
        from src.cli.rotate import rotate_command
        from src.cli.decrypt import decrypt_command

        # Setup: Initialize, encrypt, rotate
        vault_path, old_shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Bank Passwords", "Account: 123-456\nPassword: secret123")
        encrypt_test_message(vault_path, "Estate Instructions", "Executor: Jane Doe\nLawyer: John Smith")
        encrypt_test_message(vault_path, "Digital Assets", "Bitcoin wallet: bc1q...\nSeed phrase: abandon...")

        # Rotate shares
        old_stdout = sys.stdout
        sys.stdout = rotate_output_buffer = io.StringIO()

        try:
            result = rotate_command(
                vault_path=str(vault_path),
                mode="shares",
                new_k=4,
                new_n=6,
                shares=old_shares[:3],
                confirm=True
            )
            rotate_output = rotate_output_buffer.getvalue()
        finally:
            sys.stdout = old_stdout

        assert result == 0, "Rotate command should succeed"
        new_shares = extract_shares_from_output(rotate_output)

        # Decrypt with 4 new shares
        old_stdout = sys.stdout
        sys.stdout = decrypt_output_buffer = io.StringIO()

        try:
            result = decrypt_command(vault_path=str(vault_path), shares=new_shares[:4])
            decrypt_output = decrypt_output_buffer.getvalue()
        finally:
            sys.stdout = old_stdout

        # Expected: All messages decrypted successfully
        assert result == 0, "Decrypt with new shares should succeed"
        assert "Account: 123-456" in decrypt_output, "Message should be decrypted"
        assert "Executor: Jane Doe" in decrypt_output, "Message should be decrypted"
        assert "Bitcoin wallet: bc1q" in decrypt_output, "Message should be decrypted"

    def test_step_9_old_shares_invalidated_negative_test(self, tmp_path: Path) -> None:
        """Step 9: Test old shares invalidated (negative test)."""
        from src.cli.rotate import rotate_command
        from src.cli.decrypt import decrypt_command

        # Setup: Initialize, encrypt, rotate
        vault_path, old_shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Bank Passwords", "Account: 123-456\nPassword: secret123")

        # Rotate shares
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result = rotate_command(
                vault_path=str(vault_path),
                mode="shares",
                new_k=4,
                new_n=6,
                shares=old_shares[:3],
                confirm=True
            )
        finally:
            sys.stdout = old_stdout

        assert result == 0, "Rotate command should succeed"

        # Attempt decrypt with old shares (should fail)
        result = decrypt_command(vault_path=str(vault_path), shares=old_shares[:3])

        # Expected: Command should fail (old shares no longer work)
        # The decrypt will fail because the passphrase is unchanged but the manifest
        # expects different shares now. The error code should be non-zero.
        assert result != 0, f"Decrypt with old shares should fail, got exit code {result}"

    def test_step_10_final_validation(self, tmp_path: Path) -> None:
        """Step 10: Final validation."""
        from src.cli.validate import validate_command
        from src.cli.rotate import rotate_command

        # Setup: Complete all previous steps
        vault_path, old_shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Bank Passwords", "Account: 123-456\nPassword: secret123")
        encrypt_test_message(vault_path, "Estate Instructions", "Executor: Jane Doe\nLawyer: John Smith")

        # Rotate shares (step 7)
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            rotate_result = rotate_command(
                vault_path=str(vault_path),
                mode="shares",
                new_k=4,
                new_n=6,
                shares=old_shares[:3],
                confirm=True
            )
        finally:
            sys.stdout = old_stdout

        assert rotate_result == 0, "Rotate should succeed"

        # Final validation
        result = validate_command(vault_path=str(vault_path), verbose=False)

        # Expected: All checks pass
        assert result == 0, "Validation should pass (exit code 0)"

        # Verify rotation history shows 2 events (initial + rotation)
        manifest = get_vault_manifest(vault_path)
        assert "rotation_history" in manifest, "Manifest should have rotation_history"
        assert len(manifest["rotation_history"]) == 2, f"Expected 2 rotation events, got {len(manifest['rotation_history'])}"
        assert manifest["rotation_history"][0]["event"] == "initial_creation", "First event should be initial_creation"
        assert manifest["rotation_history"][1]["event"] == "share_rotation", "Second event should be share_rotation"

    def test_full_lifecycle_integrated(self, tmp_path: Path) -> None:
        """Test: Complete lifecycle (all 10 steps in sequence)."""
        from src.cli.encrypt import encrypt_command
        from src.cli.list import list_command
        from src.cli.validate import validate_command
        from src.cli.decrypt import decrypt_command
        from src.cli.rotate import rotate_command

        # Step 1: Initialize 3-of-5 vault
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        assert len(shares) == 5, "Should have 5 shares"
        assert vault_path.exists(), "Vault should exist"

        # Step 2: Encrypt 3 messages
        result1 = encrypt_command(vault_path=str(vault_path), title="Message 1", message_text="Content 1")
        result2 = encrypt_command(vault_path=str(vault_path), title="Message 2", message_text="Content 2")
        result3 = encrypt_command(vault_path=str(vault_path), title="Message 3", message_text="Content 3")
        assert result1 == 0 and result2 == 0 and result3 == 0, "All encrypts should succeed"

        # Step 3: List messages (no decryption)
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        try:
            list_result = list_command(vault_path=str(vault_path), format="json", sort_by="id")
            list_output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        assert list_result == 0, "List should succeed"
        messages_list = json.loads(list_output)
        assert len(messages_list) == 3, "Should have 3 messages"

        # Step 4: Validate vault
        validate_result = validate_command(vault_path=str(vault_path), verbose=False)
        assert validate_result == 0, "Validation should pass"

        # Step 5: Decrypt with K shares (3 out of 5)
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        try:
            decrypt_result = decrypt_command(vault_path=str(vault_path), shares=shares[:3])
            decrypt_output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        assert decrypt_result == 0, "Decrypt should succeed"
        assert "Content 1" in decrypt_output, "Message 1 should be decrypted"
        assert "Content 2" in decrypt_output, "Message 2 should be decrypted"
        assert "Content 3" in decrypt_output, "Message 3 should be decrypted"

        # Step 6: Insufficient shares (negative test)
        insufficient_result = decrypt_command(vault_path=str(vault_path), shares=shares[:2])
        assert insufficient_result == 3, "Decrypt with insufficient shares should fail"

        # Step 7: Rotate shares from 3-of-5 to 4-of-6
        old_stdout = sys.stdout
        sys.stdout = rotate_output_buffer = io.StringIO()
        try:
            rotate_result = rotate_command(
                vault_path=str(vault_path),
                mode="shares",
                new_k=4,
                new_n=6,
                shares=shares[:3],
                confirm=True
            )
            rotate_output = rotate_output_buffer.getvalue()
        finally:
            sys.stdout = old_stdout

        assert rotate_result == 0, "Rotate should succeed"
        new_shares = extract_shares_from_output(rotate_output)
        assert len(new_shares) == 6, "Should have 6 new shares"

        # Step 8: Verify new shares work (need 4 out of 6)
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        try:
            decrypt_new_result = decrypt_command(vault_path=str(vault_path), shares=new_shares[:4])
            decrypt_new_output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        assert decrypt_new_result == 0, "Decrypt with new shares should succeed"
        assert "Content 1" in decrypt_new_output, "Messages should still be decryptable"

        # Step 9: Old shares don't work (negative test)
        old_shares_result = decrypt_command(vault_path=str(vault_path), shares=shares[:3])
        assert old_shares_result != 0, "Old shares should no longer work"

        # Step 10: Final validation
        final_result = validate_command(vault_path=str(vault_path), verbose=False)
        assert final_result == 0, "Final validation should pass"

        # Verify rotation history
        manifest = get_vault_manifest(vault_path)
        assert len(manifest["rotation_history"]) == 2, "Should have 2 rotation events"
        assert manifest["threshold"]["k"] == 4, "Final threshold should be 4"
        assert manifest["threshold"]["n"] == 6, "Final total should be 6"
