"""Encrypt command implementation."""
import base64
import sys
from datetime import datetime, timezone

from src.crypto.encryption import encrypt_message
from src.storage.models import Message
from src.storage.vault import append_message, load_vault, save_vault


def encrypt_command(
    vault_path: str, title: str, message_text: str = None, stdin: bool = False
) -> int:
    """Encrypt message and add to vault."""
    import os

    # Check vault exists
    if not os.path.exists(vault_path):
        print(f"Error: Vault not found: {vault_path}", file=sys.stderr)
        return 2

    # Get message content
    if stdin:
        message_text = sys.stdin.read()
    elif message_text is None:
        print("Error: Must provide --message or --stdin", file=sys.stderr)
        return 1

    # Validate size
    message_bytes = message_text.encode("utf-8")
    if len(message_bytes) > 65536:
        print("Error: Message exceeds 64 KB limit", file=sys.stderr)
        return 4

    # Validate title
    if len(title) > 256:
        print("Error: Title exceeds 256 characters", file=sys.stderr)
        return 1

    try:
        # Load vault
        vault = load_vault(vault_path)

        # Encrypt message
        encrypted = encrypt_message(
            message_bytes,
            vault.keys.rsa_public.encode(),
            base64.b64decode(vault.keys.kyber_public),
            title,
        )

        # Create message object
        message_id = max([m.id for m in vault.messages], default=0) + 1
        message = Message(
            id=message_id,
            title=title,
            ciphertext=base64.b64encode(encrypted.ciphertext).decode(),
            rsa_wrapped_kek=base64.b64encode(encrypted.rsa_wrapped_kek).decode(),
            kyber_wrapped_kek=base64.b64encode(encrypted.kyber_wrapped_kek).decode(),
            nonce=base64.b64encode(encrypted.nonce).decode(),
            auth_tag=base64.b64encode(encrypted.auth_tag).decode(),
            created=datetime.now(timezone.utc).isoformat(),
            size_bytes=len(message_bytes),
        )

        # Append to vault
        vault = append_message(vault, message)

        # Save vault
        save_vault(vault, vault_path)

        print(f"✓ Message encrypted: ID={message_id}, Title='{title}'")
        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 5
