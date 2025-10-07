"""List command implementation."""
import json
import sys

from src.storage.vault import load_vault


def list_command(vault_path: str, format: str = "table", sort_by: str = "id") -> int:
    """List messages in vault."""
    import os

    if not os.path.exists(vault_path):
        print(f"Error: Vault not found: {vault_path}", file=sys.stderr)
        return 2

    try:
        vault = load_vault(vault_path)

        # Sort messages
        if sort_by == "id":
            messages = sorted(vault.messages, key=lambda m: m.id)
        elif sort_by == "title":
            messages = sorted(vault.messages, key=lambda m: m.title)
        elif sort_by == "created":
            messages = sorted(vault.messages, key=lambda m: m.created)
        elif sort_by == "size":
            messages = sorted(vault.messages, key=lambda m: m.size_bytes)
        else:
            messages = vault.messages

        if format == "json":
            data = [
                {
                    "id": m.id,
                    "title": m.title,
                    "created": m.created,
                    "size_bytes": m.size_bytes,
                }
                for m in messages
            ]
            print(json.dumps(data, indent=2))
        else:
            # Table format
            print(f"{'ID':<4} {'Title':<40} {'Created':<27} {'Size':<10}")
            print("-" * 85)
            for m in messages:
                print(
                    f"{m.id:<4} {m.title[:39]:<40} {m.created:<27} {m.size_bytes:<10}"
                )

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
