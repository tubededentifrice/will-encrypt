"""Encrypt command implementation."""
import base64
import sys
from datetime import UTC, datetime

from src.crypto.encryption import encrypt_message
from src.storage.models import Message
from src.storage.vault import append_message, load_vault, save_vault


def encrypt_command(
    vault_path: str, title: str | None = None, message_text: str | None = None, stdin: bool = False
) -> int:
    """Encrypt message and add to vault."""
    import os

    # Check vault exists
    if not os.path.exists(vault_path):
        print(f"\nError: Vault not found: {vault_path}", file=sys.stderr)
        print("Hint: Initialize vault first with: will-encrypt init --k 3 --n 5", file=sys.stderr)
        return 2

    # Interactive prompt for title if not provided
    if title is None:
        try:
            print("\n📝 Encrypt New Message\n")
            title = input("Enter message title (max 256 chars): ").strip()
            if not title:
                print("\nError: Title cannot be empty", file=sys.stderr)
                return 1
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.", file=sys.stderr)
            return 1

    # Validate title
    if len(title) > 256:
        print(f"\nError: Title exceeds 256 characters (got {len(title)})", file=sys.stderr)
        print("Hint: Use shorter, descriptive title", file=sys.stderr)
        return 1

    # Get message content
    if stdin:
        print("Reading message from stdin...")
        message_text = sys.stdin.read()
    elif message_text is None:
        try:
            print("\nEnter message content (multi-line supported, Ctrl+D to finish):")
            print("-" * 50)
            lines = []
            while True:
                try:
                    line = input()
                    lines.append(line)
                except EOFError:
                    break
            message_text = "\n".join(lines)
            print("-" * 50)
            if not message_text:
                print("\nError: Message cannot be empty", file=sys.stderr)
                return 1
        except KeyboardInterrupt:
            print("\nAborted.", file=sys.stderr)
            return 1

    # Validate size
    message_bytes = message_text.encode("utf-8")
    if len(message_bytes) > 65536:
        print(f"\nError: Message exceeds 64 KB limit (got {len(message_bytes):,} bytes)", file=sys.stderr)
        print("Hint: Split into multiple smaller messages or store large files separately", file=sys.stderr)
        return 4

    try:
        # Progress indicators
        print("\n🔐 Encrypting message...")

        # Load vault
        print("  [1/4] Loading vault...")
        vault = load_vault(vault_path)

        # Show progress for large messages
        if len(message_bytes) > 10000:
            print(f"  [2/4] Encrypting {len(message_bytes):,} bytes with AES-256-GCM...")
        else:
            print("  [2/4] Encrypting message with AES-256-GCM...")

        # Encrypt message
        encrypted = encrypt_message(
            message_bytes,
            vault.keys.rsa_public.encode(),
            base64.b64decode(vault.keys.kyber_public),
            title,
        )

        print("  [3/4] Wrapping encryption key with RSA-4096 + Kyber-1024...")

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
            created=datetime.now(UTC).isoformat(),
            size_bytes=len(message_bytes),
        )

        # Append to vault
        vault = append_message(vault, message)

        # Save vault
        print("  [4/4] Saving vault...")
        save_vault(vault, vault_path)

        print("\n✓ Message encrypted successfully!")
        print(f"  • Message ID: {message_id}")
        print(f"  • Title: '{title}'")
        print(f"  • Size: {len(message_bytes):,} bytes")
        print(f"  • Total messages in vault: {len(vault.messages)}")
        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 5
