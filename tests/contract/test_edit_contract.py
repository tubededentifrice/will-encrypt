"""
Contract tests for edit command.

Tests MUST fail before implementation (TDD).
"""

import io
import sys
from pathlib import Path

from tests.test_helpers import create_test_vault, encrypt_test_message


class TestEditCommand:
    """Contract tests for will-encrypt edit command."""

    def test_edit_message_title(self, tmp_path: Path) -> None:
        """Test: Edit message title by ID."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault and encrypt messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Original Title", "Secret content")
        encrypt_test_message(vault_path, "Message 2", "Secret 2")

        # Edit message title
        from src.cli.edit import edit_command

        # Capture output
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result = edit_command(
                vault_path=str(vault_path), message_id="1", new_title="Updated Title"
            )
            output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        # Expected: Success message showing old and new titles
        assert result == 0
        assert "title updated" in output
        assert "Original Title" in output
        assert "Updated Title" in output

        # Verify message title is changed
        from src.storage.vault import load_vault

        vault = load_vault(str(vault_path))
        message_1 = next(m for m in vault.messages if m.id == 1)
        assert message_1.title == "Updated Title"

    def test_edit_message_title_not_found(self, tmp_path: Path) -> None:
        """Test: Edit message with non-existent ID returns error."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault with messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Message 1", "Secret 1")

        # Try to edit non-existent message
        from src.cli.edit import edit_command

        # Capture error output
        old_stderr = sys.stderr
        sys.stderr = captured_error = io.StringIO()

        try:
            result = edit_command(
                vault_path=str(vault_path), message_id="999", new_title="New Title"
            )
            error_output = captured_error.getvalue()
        finally:
            sys.stderr = old_stderr

        # Expected: Error message
        assert result == 2
        assert "not found" in error_output

    def test_edit_message_vault_not_found(self, tmp_path: Path) -> None:
        """Test: Edit in non-existent vault returns error."""
        vault_path = tmp_path / "nonexistent.yaml"

        from src.cli.edit import edit_command

        # Capture error output
        old_stderr = sys.stderr
        sys.stderr = captured_error = io.StringIO()

        try:
            result = edit_command(
                vault_path=str(vault_path), message_id="1", new_title="New Title"
            )
            error_output = captured_error.getvalue()
        finally:
            sys.stderr = old_stderr

        # Expected: Error message
        assert result == 2
        assert "Vault not found" in error_output

    def test_edit_multiple_messages(self, tmp_path: Path) -> None:
        """Test: Edit multiple message titles."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault with messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Title 1", "Secret 1")
        encrypt_test_message(vault_path, "Title 2", "Secret 2")
        encrypt_test_message(vault_path, "Title 3", "Secret 3")

        from src.cli.edit import edit_command
        from src.storage.vault import load_vault

        # Edit multiple titles
        edit_command(vault_path=str(vault_path), message_id="1", new_title="Updated 1")
        edit_command(vault_path=str(vault_path), message_id="3", new_title="Updated 3")

        # Verify changes
        vault = load_vault(str(vault_path))
        message_1 = next(m for m in vault.messages if m.id == 1)
        message_2 = next(m for m in vault.messages if m.id == 2)
        message_3 = next(m for m in vault.messages if m.id == 3)

        assert message_1.title == "Updated 1"
        assert message_2.title == "Title 2"  # Unchanged
        assert message_3.title == "Updated 3"

    def test_edit_preserves_ciphertext(self, tmp_path: Path) -> None:
        """Test: Editing title does not affect encrypted content."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault with message
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Original Title", "Secret content")

        from src.cli.edit import edit_command
        from src.storage.vault import load_vault

        # Get original ciphertext
        vault_before = load_vault(str(vault_path))
        original_ciphertext = vault_before.messages[0].ciphertext

        # Edit title
        edit_command(vault_path=str(vault_path), message_id="1", new_title="New Title")

        # Verify ciphertext unchanged
        vault_after = load_vault(str(vault_path))
        assert vault_after.messages[0].ciphertext == original_ciphertext
        assert vault_after.messages[0].title == "New Title"
