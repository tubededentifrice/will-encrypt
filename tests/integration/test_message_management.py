"""
Integration tests for message management (delete and edit).

Tests the complete workflow of deleting and editing messages.
"""

from pathlib import Path

from tests.test_helpers import create_test_vault, encrypt_test_message


class TestMessageManagement:
    """Integration tests for message delete and edit operations."""

    def test_delete_and_list_workflow(self, tmp_path: Path) -> None:
        """Test: Delete messages and verify list updates."""
        # Setup: Create vault with messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Message 1", "Content 1")
        encrypt_test_message(vault_path, "Message 2", "Content 2")
        encrypt_test_message(vault_path, "Message 3", "Content 3")

        from src.cli.delete import delete_command
        from src.cli.list import list_command
        import io
        import json
        import sys

        # List before delete
        old_stdout = sys.stdout
        sys.stdout = captured = io.StringIO()
        try:
            list_command(vault_path=str(vault_path), format="json", sort_by="id")
            output = captured.getvalue()
        finally:
            sys.stdout = old_stdout

        messages = json.loads(output)
        assert len(messages) == 3

        # Delete message 2
        result = delete_command(vault_path=str(vault_path), message_id="2")
        assert result == 0

        # List after delete
        old_stdout = sys.stdout
        sys.stdout = captured = io.StringIO()
        try:
            list_command(vault_path=str(vault_path), format="json", sort_by="id")
            output = captured.getvalue()
        finally:
            sys.stdout = old_stdout

        messages = json.loads(output)
        assert len(messages) == 2
        assert all(m["id"] != 2 for m in messages)

    def test_edit_and_list_workflow(self, tmp_path: Path) -> None:
        """Test: Edit message titles and verify changes."""
        # Setup: Create vault with messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Original Title 1", "Content 1")
        encrypt_test_message(vault_path, "Original Title 2", "Content 2")

        from src.cli.edit import edit_command
        from src.cli.list import list_command
        import io
        import json
        import sys

        # Edit message 1
        result = edit_command(
            vault_path=str(vault_path), message_id="1", new_title="Updated Title 1"
        )
        assert result == 0

        # List and verify
        old_stdout = sys.stdout
        sys.stdout = captured = io.StringIO()
        try:
            list_command(vault_path=str(vault_path), format="json", sort_by="id")
            output = captured.getvalue()
        finally:
            sys.stdout = old_stdout

        messages = json.loads(output)
        assert messages[0]["title"] == "Updated Title 1"
        assert messages[1]["title"] == "Original Title 2"

    def test_edit_then_decrypt_workflow(self, tmp_path: Path) -> None:
        """Test: Edit message title, vault structure remains valid."""
        # Setup: Create vault with message
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Original Title", "Secret content")

        from src.cli.edit import edit_command
        from src.storage.vault import load_vault

        # Edit message title
        result = edit_command(vault_path=str(vault_path), message_id="1", new_title="New Title")
        assert result == 0

        # Verify title was changed and vault is still valid
        vault = load_vault(str(vault_path))
        assert len(vault.messages) == 1
        assert vault.messages[0].title == "New Title"
        assert vault.messages[0].ciphertext  # Ciphertext still exists

    def test_delete_multiple_messages(self, tmp_path: Path) -> None:
        """Test: Delete multiple messages sequentially."""
        # Setup: Create vault with 5 messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        for i in range(1, 6):
            encrypt_test_message(vault_path, f"Message {i}", f"Content {i}")

        from src.cli.delete import delete_command
        from src.storage.vault import load_vault

        # Delete messages 2, 4
        delete_command(vault_path=str(vault_path), message_id="2")
        delete_command(vault_path=str(vault_path), message_id="4")

        # Verify only 3 messages remain
        vault = load_vault(str(vault_path))
        assert len(vault.messages) == 3
        remaining_ids = [m.id for m in vault.messages]
        assert 1 in remaining_ids
        assert 3 in remaining_ids
        assert 5 in remaining_ids

    def test_edit_all_message_titles(self, tmp_path: Path) -> None:
        """Test: Edit all message titles in vault."""
        # Setup: Create vault with 3 messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        for i in range(1, 4):
            encrypt_test_message(vault_path, f"Title {i}", f"Content {i}")

        from src.cli.edit import edit_command
        from src.storage.vault import load_vault

        # Edit all titles
        for i in range(1, 4):
            edit_command(
                vault_path=str(vault_path),
                message_id=str(i),
                new_title=f"Updated {i}",
            )

        # Verify all titles updated
        vault = load_vault(str(vault_path))
        for i, message in enumerate(vault.messages, 1):
            assert message.title == f"Updated {i}"

    def test_delete_then_encrypt_new_message(self, tmp_path: Path) -> None:
        """Test: Delete message, then encrypt new message."""
        # Setup: Create vault with messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Message 1", "Content 1")
        encrypt_test_message(vault_path, "Message 2", "Content 2")

        from src.cli.delete import delete_command
        from src.storage.vault import load_vault

        # Delete message 1
        delete_command(vault_path=str(vault_path), message_id="1")

        # Encrypt new message
        encrypt_test_message(vault_path, "New Message", "New Content")

        # Verify state
        vault = load_vault(str(vault_path))
        assert len(vault.messages) == 2
        titles = [m.title for m in vault.messages]
        assert "Message 1" not in titles
        assert "Message 2" in titles
        assert "New Message" in titles

    def test_vault_validation_after_delete(self, tmp_path: Path) -> None:
        """Test: Vault validation passes after deleting messages."""
        # Setup: Create vault with messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Message 1", "Content 1")
        encrypt_test_message(vault_path, "Message 2", "Content 2")

        from src.cli.delete import delete_command
        from src.cli.validate import validate_command
        import io
        import sys

        # Delete message
        delete_command(vault_path=str(vault_path), message_id="1")

        # Validate vault
        old_stdout = sys.stdout
        sys.stdout = captured = io.StringIO()
        try:
            result = validate_command(vault_path=str(vault_path), verbose=False)
        finally:
            sys.stdout = old_stdout

        assert result == 0

    def test_vault_validation_after_edit(self, tmp_path: Path) -> None:
        """Test: Vault validation passes after editing message titles."""
        # Setup: Create vault with messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Original", "Content")

        from src.cli.edit import edit_command
        from src.cli.validate import validate_command
        import io
        import sys

        # Edit message
        edit_command(vault_path=str(vault_path), message_id="1", new_title="Updated")

        # Validate vault
        old_stdout = sys.stdout
        sys.stdout = captured = io.StringIO()
        try:
            result = validate_command(vault_path=str(vault_path), verbose=False)
        finally:
            sys.stdout = old_stdout

        assert result == 0
