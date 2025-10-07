"""
Contract tests for encrypt command.

Based on: specs/001-1-purpose-scope/contracts/encrypt.schema.yaml

Tests MUST fail before implementation (TDD).
"""

import base64
import io
import sys
import time
from pathlib import Path

import pytest
import yaml

from tests.test_helpers import create_test_vault, get_vault_messages


class TestEncryptCommand:
    """Contract tests for will-encrypt encrypt command."""

    def test_encrypt_message_via_argument(self, tmp_path: Path) -> None:
        """Test: Encrypt message via --message argument, verify vault updated."""
        from src.cli.encrypt import encrypt_command

        # Setup: Create initialized vault
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)

        # Encrypt message
        result = encrypt_command(
            vault_path=str(vault_path),
            title="Test Message",
            message_text="Secret content"
        )

        assert result == 0, "Encrypt command should succeed"

        # Verify vault contains encrypted message
        messages = get_vault_messages(vault_path)
        assert len(messages) == 1, "Vault should have 1 message"

        message = messages[0]
        assert message["id"] == 1, "First message should have ID 1"
        assert message["title"] == "Test Message"
        assert "ciphertext" in message
        assert "rsa_wrapped_kek" in message
        assert "kyber_wrapped_kek" in message
        assert "nonce" in message
        assert "tag" in message

        # Verify fields are base64-encoded
        ciphertext = base64.b64decode(message["ciphertext"])
        assert len(ciphertext) > 0, "Ciphertext should not be empty"

        nonce = base64.b64decode(message["nonce"])
        assert len(nonce) == 12, "Nonce should be 96 bits (12 bytes)"

        auth_tag = base64.b64decode(message["tag"])
        assert len(auth_tag) == 16, "Auth tag should be 128 bits (16 bytes)"

    def test_encrypt_message_via_stdin(self, tmp_path: Path) -> None:
        """Test: Encrypt message via stdin, verify vault updated."""
        from src.cli.encrypt import encrypt_command

        # Setup: Create initialized vault
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)

        # Mock stdin with message content
        old_stdin = sys.stdin
        sys.stdin = io.StringIO("Secret content from stdin")

        try:
            result = encrypt_command(
                vault_path=str(vault_path),
                title="Stdin Test",
                stdin=True
            )
            assert result == 0, "Encrypt command should succeed"
        finally:
            sys.stdin = old_stdin

        # Verify message was encrypted
        messages = get_vault_messages(vault_path)
        assert len(messages) == 1, "Vault should have 1 message"
        assert messages[0]["title"] == "Stdin Test"

    def test_encrypt_rejects_message_over_64kb(self, tmp_path: Path) -> None:
        """Test: Message size > 64 KB rejection."""
        from src.cli.encrypt import encrypt_command

        # Setup: Create initialized vault
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)

        # Create message > 64 KB
        large_message = "A" * (65 * 1024)  # 65 KB

        # Expected: Exit code 4 (size exceeded)
        result = encrypt_command(
            vault_path=str(vault_path),
            title="Too Large",
            message_text=large_message
        )

        assert result == 4, "Encrypt should fail with exit code 4 for oversized messages"

        # Verify no message was added to vault
        messages = get_vault_messages(vault_path)
        assert len(messages) == 0, "No message should be added when size limit exceeded"

    def test_encrypt_performance_under_1_second_for_64kb(self, tmp_path: Path) -> None:
        """Test: Performance < 1 second for 64 KB message."""
        from src.cli.encrypt import encrypt_command

        # Setup: Create initialized vault
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)

        # Create 64 KB message (at limit)
        message_64kb = "A" * (64 * 1024)

        # Time the encryption
        start = time.time()
        result = encrypt_command(
            vault_path=str(vault_path),
            title="Performance Test",
            message_text=message_64kb
        )
        duration = time.time() - start

        assert result == 0, "Encrypt should succeed for 64KB message"
        assert duration < 1.0, f"Encrypt took {duration:.2f}s (target < 1s)"

    def test_encrypt_multiple_messages_sequential_ids(self, tmp_path: Path) -> None:
        """Test: Multiple messages get sequential IDs."""
        from src.cli.encrypt import encrypt_command

        # Setup: Create initialized vault
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)

        # Encrypt 3 messages
        result1 = encrypt_command(
            vault_path=str(vault_path),
            title="Message 1",
            message_text="Content 1"
        )
        result2 = encrypt_command(
            vault_path=str(vault_path),
            title="Message 2",
            message_text="Content 2"
        )
        result3 = encrypt_command(
            vault_path=str(vault_path),
            title="Message 3",
            message_text="Content 3"
        )

        assert result1 == 0, "First encrypt should succeed"
        assert result2 == 0, "Second encrypt should succeed"
        assert result3 == 0, "Third encrypt should succeed"

        # Verify sequential IDs
        messages = get_vault_messages(vault_path)
        assert len(messages) == 3, "Vault should have 3 messages"
        assert messages[0]["id"] == 1, "First message should have ID 1"
        assert messages[1]["id"] == 2, "Second message should have ID 2"
        assert messages[2]["id"] == 3, "Third message should have ID 3"

    def test_encrypt_vault_not_found(self) -> None:
        """Test: Vault not found error."""
        from src.cli.encrypt import encrypt_command

        # Expected: Exit code 2 (vault not found)
        result = encrypt_command(
            vault_path="/nonexistent/vault.yaml",
            title="Test",
            message_text="Content"
        )

        assert result == 2, "Encrypt should fail with exit code 2 when vault not found"

    def test_encrypt_title_length_validation(self, tmp_path: Path) -> None:
        """Test: Title length <= 256 characters."""
        from src.cli.encrypt import encrypt_command

        # Setup: Create initialized vault
        vault_path, shares = create_test_vault(tmp_path, k=3, n=5)

        # Title with 257 characters (exceeds limit)
        long_title = "A" * 257

        # Expected: Exit code 1 for validation error
        result = encrypt_command(
            vault_path=str(vault_path),
            title=long_title,
            message_text="Content"
        )

        assert result == 1, "Encrypt should fail with exit code 1 for title too long"

        # Verify no message was added
        messages = get_vault_messages(vault_path)
        assert len(messages) == 0, "No message should be added when title validation fails"
