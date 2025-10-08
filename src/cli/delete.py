"""Delete command implementation."""
import sys

from src.storage.vault import delete_message, load_vault, save_vault


def delete_command(vault_path: str, message_id: str | int) -> int:
    """Delete message from vault by ID."""
    import os

    if not os.path.exists(vault_path):
        print(f"Error: Vault not found: {vault_path}", file=sys.stderr)
        return 2

    try:
        vault = load_vault(vault_path)

        # Convert message_id to int if it's a string
        msg_id = int(message_id) if isinstance(message_id, str) else message_id

        # Find message to show confirmation
        message = next((m for m in vault.messages if m.id == msg_id), None)
        if not message:
            print(f"Error: Message with ID '{msg_id}' not found in vault", file=sys.stderr)
            return 2

        # Delete message
        vault = delete_message(vault, msg_id)
        save_vault(vault, vault_path)

        print(f"✓ Message '{message.title}' (ID: {msg_id}) deleted successfully")
        return 0

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
