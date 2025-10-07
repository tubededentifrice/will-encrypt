"""Validate command implementation."""
import sys

from src.storage.manifest import validate_fingerprints
from src.storage.vault import load_vault


def validate_command(vault_path: str, verbose: bool = False) -> int:
    """Validate vault integrity."""
    import os

    if not os.path.exists(vault_path):
        print(f"Error: Vault not found: {vault_path}", file=sys.stderr)
        return 2

    try:
        vault = load_vault(vault_path)

        # Check version
        if vault.version != "1.0":
            print(f"✗ Unsupported version: {vault.version}", file=sys.stderr)
            return 8

        # Check manifest exists
        if not vault.manifest:
            print("✗ Missing manifest", file=sys.stderr)
            return 6

        # Check threshold
        if vault.manifest.k < 1 or vault.manifest.k > vault.manifest.n:
            print(
                f"✗ Invalid threshold: K={vault.manifest.k}, N={vault.manifest.n}",
                file=sys.stderr,
            )
            return 4

        # Validate fingerprints
        if not validate_fingerprints(vault):
            print("✗ Fingerprint mismatch (vault may be tampered)", file=sys.stderr)
            return 3

        print("✓ Vault validation passed")
        if verbose:
            print(f"  Version: {vault.version}")
            print(f"  Threshold: {vault.manifest.k}-of-{vault.manifest.n}")
            print(f"  Messages: {len(vault.messages)}")
            print(f"  Rotation events: {len(vault.manifest.rotation_history)}")

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
