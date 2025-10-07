"""
Contract tests for list command.

Based on: specs/001-1-purpose-scope/contracts/list.schema.yaml

Tests MUST fail before implementation (TDD).
"""

import io
import json
import sys
from pathlib import Path

import pytest

from tests.test_helpers import create_test_vault, encrypt_test_message


class TestListCommand:
    """Contract tests for will-encrypt list command."""

    def test_list_messages_table_format(self, tmp_path: Path) -> None:
        """Test: List messages in table format."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault and encrypt messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Bank Passwords", "Secret 1")
        encrypt_test_message(vault_path, "Estate Instructions", "Secret 2")
        encrypt_test_message(vault_path, "Digital Assets", "Secret 3")

        # List messages in table format
        from src.cli.list import list_command

        # Capture output
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result = list_command(vault_path=str(vault_path), format="table", sort_by="id")
            output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        # Expected: Table with columns: ID, Title, Created, Size
        assert result == 0
        assert "ID" in output
        assert "Title" in output
        assert "Bank Passwords" in output
        assert "Estate Instructions" in output
        assert "Digital Assets" in output
        # No plaintext content visible
        assert "Secret 1" not in output
        assert "Secret 2" not in output
        assert "Secret 3" not in output

    def test_list_messages_json_format(self, tmp_path: Path) -> None:
        """Test: List messages in JSON format."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault and encrypt messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Test 1", "Secret 1")
        encrypt_test_message(vault_path, "Test 2", "Secret 2")

        # List messages in JSON format
        from src.cli.list import list_command

        # Capture output
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result = list_command(vault_path=str(vault_path), format="json", sort_by="id")
            output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        # Expected: Valid JSON array
        assert result == 0
        messages = json.loads(output)
        assert len(messages) == 2
        assert messages[0]["id"] == 1
        assert messages[0]["title"] == "Test 1"
        assert "created" in messages[0]
        assert "size_bytes" in messages[0]
        assert "plaintext" not in messages[0]  # No plaintext in list output

    def test_list_sort_by_id(self, tmp_path: Path) -> None:
        """Test: Sort by ID (default order)."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault and encrypt messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Message 3", "C")
        encrypt_test_message(vault_path, "Message 1", "A")
        encrypt_test_message(vault_path, "Message 2", "B")

        # List sorted by ID
        from src.cli.list import list_command

        # Capture output
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result = list_command(vault_path=str(vault_path), format="json", sort_by="id")
            output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        # Expected: Messages in ID order (1, 2, 3)
        assert result == 0
        messages = json.loads(output)
        assert messages[0]["id"] == 1
        assert messages[1]["id"] == 2
        assert messages[2]["id"] == 3

    def test_list_sort_by_title(self, tmp_path: Path) -> None:
        """Test: Sort by title (alphabetical)."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault and encrypt messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Zebra", "Content 1")
        encrypt_test_message(vault_path, "Apple", "Content 2")
        encrypt_test_message(vault_path, "Mango", "Content 3")

        # List sorted by title
        from src.cli.list import list_command

        # Capture output
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result = list_command(vault_path=str(vault_path), format="json", sort_by="title")
            output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        # Expected: Messages in alphabetical order
        assert result == 0
        messages = json.loads(output)
        assert messages[0]["title"] == "Apple"
        assert messages[1]["title"] == "Mango"
        assert messages[2]["title"] == "Zebra"

    def test_list_sort_by_created_timestamp(self, tmp_path: Path) -> None:
        """Test: Sort by created timestamp."""
        import time

        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault and encrypt messages with delays
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "First", "A")
        time.sleep(0.1)
        encrypt_test_message(vault_path, "Second", "B")
        time.sleep(0.1)
        encrypt_test_message(vault_path, "Third", "C")

        # List sorted by created timestamp
        from src.cli.list import list_command

        # Capture output
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result = list_command(vault_path=str(vault_path), format="json", sort_by="created")
            output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        # Expected: Messages in chronological order
        assert result == 0
        messages = json.loads(output)
        assert messages[0]["title"] == "First"
        assert messages[1]["title"] == "Second"
        assert messages[2]["title"] == "Third"

    def test_list_sort_by_size(self, tmp_path: Path) -> None:
        """Test: Sort by message size."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault and encrypt messages of different sizes
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)
        encrypt_test_message(vault_path, "Large", "A" * 1000)
        encrypt_test_message(vault_path, "Small", "B" * 10)
        encrypt_test_message(vault_path, "Medium", "C" * 100)

        # List sorted by size
        from src.cli.list import list_command

        # Capture output
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result = list_command(vault_path=str(vault_path), format="json", sort_by="size")
            output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        # Expected: Messages in size order (small to large)
        assert result == 0
        messages = json.loads(output)
        assert messages[0]["title"] == "Small"
        assert messages[1]["title"] == "Medium"
        assert messages[2]["title"] == "Large"

    def test_list_empty_vault(self, tmp_path: Path) -> None:
        """Test: List empty vault (no messages)."""
        vault_path = tmp_path / "vault.yaml"

        # Setup: Create vault with no messages
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)

        # List messages
        from src.cli.list import list_command

        # Capture output
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            result = list_command(vault_path=str(vault_path), format="json", sort_by="id")
            output = captured_output.getvalue()
        finally:
            sys.stdout = old_stdout

        # Expected: Empty array
        assert result == 0
        messages = json.loads(output)
        assert len(messages) == 0
