"""Edit command implementation."""
import sys

from src.storage.vault import edit_message_title, load_vault, save_vault


def edit_command(vault_path: str, message_id: str | int, new_title: str) -> int:
    """Edit message title by ID."""
    import os

    if not os.path.exists(vault_path):
        print(f"Error: Vault not found: {vault_path}", file=sys.stderr)
        return 2

    try:
        vault = load_vault(vault_path)

        # Convert message_id to int if it's a string
        msg_id = int(message_id) if isinstance(message_id, str) else message_id

        # Find message to show old title
        message = next((m for m in vault.messages if m.id == msg_id), None)
        if not message:
            print(f"Error: Message with ID '{msg_id}' not found in vault", file=sys.stderr)
            return 2

        old_title = message.title

        # Edit message title
        vault = edit_message_title(vault, msg_id, new_title)
        save_vault(vault, vault_path)

        print(f"✓ Message title updated (ID: {msg_id})")
        print(f"  Old: {old_title}")
        print(f"  New: {new_title}")
        return 0

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
