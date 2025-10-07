"""Validate command implementation."""
import sys

from src.storage.manifest import validate_fingerprints
from src.storage.vault import load_vault


def validate_command(vault_path: str, verbose: bool = False) -> int:
    """Validate vault integrity."""
    import os

    if not os.path.exists(vault_path):
        print(f"\nError: Vault not found: {vault_path}", file=sys.stderr)
        print(f"Hint: Check the file path and ensure vault exists", file=sys.stderr)
        return 2

    try:
        print(f"\n🔍 Validating Vault: {vault_path}\n")
        print("-" * 70)

        # Progress: Load vault
        print(f"[1/5] Loading vault structure...")
        vault = load_vault(vault_path)
        print(f"      ✓ Vault loaded successfully")

        # Check version
        print(f"[2/5] Checking vault version...")
        if vault.version != "1.0":
            print(f"      ✗ Unsupported version: {vault.version}", file=sys.stderr)
            print(f"      Expected: 1.0", file=sys.stderr)
            return 8
        print(f"      ✓ Version: {vault.version}")

        # Check manifest exists
        print(f"[3/5] Validating manifest structure...")
        if not vault.manifest:
            print(f"      ✗ Missing manifest", file=sys.stderr)
            return 6

        # Check threshold
        if vault.manifest.k < 1 or vault.manifest.k > vault.manifest.n:
            print(
                f"      ✗ Invalid threshold: K={vault.manifest.k}, N={vault.manifest.n}",
                file=sys.stderr,
            )
            print(f"      Hint: K must be between 1 and N", file=sys.stderr)
            return 4
        print(f"      ✓ Threshold: {vault.manifest.k}-of-{vault.manifest.n}")

        # Validate keypair structure
        print(f"[4/5] Validating keypair structure...")
        if not vault.keys:
            print(f"      ✗ Missing keypair", file=sys.stderr)
            return 6
        required_keys = ['rsa_public', 'rsa_private_encrypted', 'kyber_public',
                        'kyber_private_encrypted', 'kdf_salt', 'kdf_iterations']
        for key in required_keys:
            if not hasattr(vault.keys, key):
                print(f"      ✗ Missing keypair field: {key}", file=sys.stderr)
                return 6
        print(f"      ✓ Keypair structure valid")

        # Validate fingerprints (tamper detection)
        print(f"[5/5] Verifying cryptographic fingerprints...")
        if not validate_fingerprints(vault):
            print(f"      ✗ Fingerprint mismatch (vault may be tampered)", file=sys.stderr)
            print(f"      Recovery: Restore from backup", file=sys.stderr)
            return 3
        print(f"      ✓ All fingerprints match (vault integrity verified)")

        # Success summary
        print(f"\n{'='*70}")
        print(f"✓ Vault Validation: PASSED")
        print(f"{'='*70}\n")

        if verbose:
            print(f"📊 Vault Statistics:\n")
            print(f"  Version: {vault.version}")
            print(f"  Threshold: {vault.manifest.k}-of-{vault.manifest.n}")
            print(f"  Messages: {len(vault.messages)}")
            print(f"  Rotation events: {len(vault.manifest.rotation_history)}")

            # Total encrypted data size
            total_size = sum(m.size_bytes for m in vault.messages)
            print(f"  Total encrypted data: {total_size:,} bytes")

            # Algorithms
            print(f"\n🔐 Cryptographic Algorithms:\n")
            for key, value in vault.manifest.algorithms.items():
                print(f"  • {key}: {value}")

            # Rotation history
            if vault.manifest.rotation_history:
                print(f"\n🔄 Rotation History:\n")
                for i, event in enumerate(vault.manifest.rotation_history, 1):
                    print(f"  {i}. {event.event_type} ({event.date})")
                    print(f"     Threshold: {event.k}-of-{event.n}")

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
