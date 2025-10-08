"""
Contract tests for delete command.

Tests MUST fail before implementation (TDD).
"""

import io
import sys
from pathlib import Path

from tests.test_helpers import create_test_vault, encrypt_test_message


class TestDeleteCommand:
    """Contract tests for will-encrypt delete command."""

    def test_delete_message_by_id(self, tmp_path: Path) -> None:
        """Test: Delete message from vault by ID."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault and encrypt messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Message 1", "Secret 1")
        encrypt_test_message(vault_path, "Message 2", "Secret 2")
        encrypt_test_message(vault_path, "Message 3", "Secret 3")

        # Delete message with ID 2
        from src.cli.delete import delete_command

        # Capture output
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result = delete_command(vault_path=str(vault_path), message_id="2")
            output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        # Expected: Success message
        assert result == 0
        assert "deleted successfully" in output
        assert "Message 2" in output

        # Verify message is deleted
        from src.storage.vault import load_vault

        vault = load_vault(str(vault_path))
        assert len(vault.messages) == 2
        assert all(m.id != "2" for m in vault.messages)

    def test_delete_message_not_found(self, tmp_path: Path) -> None:
        """Test: Delete message with non-existent ID returns error."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault with messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Message 1", "Secret 1")

        # Try to delete non-existent message
        from src.cli.delete import delete_command

        # Capture error output
        old_stderr = sys.stderr
        sys.stderr = captured_error = io.StringIO()

        try:
            result = delete_command(vault_path=str(vault_path), message_id="999")
            error_output = captured_error.getvalue()
        finally:
            sys.stderr = old_stderr

        # Expected: Error message
        assert result == 2
        assert "not found" in error_output

    def test_delete_message_vault_not_found(self, tmp_path: Path) -> None:
        """Test: Delete from non-existent vault returns error."""
        vault_path = tmp_path / "nonexistent.yaml"

        from src.cli.delete import delete_command

        # Capture error output
        old_stderr = sys.stderr
        sys.stderr = captured_error = io.StringIO()

        try:
            result = delete_command(vault_path=str(vault_path), message_id="1")
            error_output = captured_error.getvalue()
        finally:
            sys.stderr = old_stderr

        # Expected: Error message
        assert result == 2
        assert "Vault not found" in error_output

    def test_delete_all_messages(self, tmp_path: Path) -> None:
        """Test: Delete all messages from vault."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault with messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Message 1", "Secret 1")
        encrypt_test_message(vault_path, "Message 2", "Secret 2")

        from src.cli.delete import delete_command
        from src.storage.vault import load_vault

        # Delete all messages
        delete_command(vault_path=str(vault_path), message_id="1")
        delete_command(vault_path=str(vault_path), message_id="2")

        # Verify vault is empty
        vault = load_vault(str(vault_path))
        assert len(vault.messages) == 0
